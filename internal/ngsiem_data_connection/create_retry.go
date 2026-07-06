package ngsiemdataconnection

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/runtime"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Live testing showed POST /ngsiem/entities/connections/v1 returns intermittent 500s when ~10
// connections are created concurrently (Terraform's default parallelism). The create body carries no
// idempotency key, and a 500 can be returned AFTER the connection row is written server-side, so a blind
// retry risks creating a duplicate. createConnectionWithRetry therefore guards every retry that could
// have created a resource with a list-by-name diff against a snapshot taken before the first POST: a
// same-named connection that appears despite the error was created by this call and is adopted instead of
// re-POSTed. Unlike the open-ended token poll loop, retries are bounded so a persistent failure can't
// keep widening the duplicate window.

// maxCreateRetries bounds the number of retries after the initial POST (so up to maxCreateRetries+1
// attempts total).
const maxCreateRetries = 4

// createRetryBaseDelay is the first backoff step; it doubles each attempt up to createRetryMaxDelay. A
// var so tests can shorten the cadence, mirroring tokenWaitInterval.
var createRetryBaseDelay = 1 * time.Second

// createRetryMaxDelay caps the exponential backoff.
const createRetryMaxDelay = 8 * time.Second

// isRetryableCreateError reports whether a create POST error is a transient failure worth retrying. It
// mirrors decodeTokenResponse's retryable set: 429 (throttle) and any 5xx (transient server error) are
// retryable; a deterministic 4xx (400/403/404/409) fails fast. An error carrying no HTTP status (a
// transport reset or dial timeout) is treated as retryable because the request may never have reached the
// server — the caller still runs the duplicate guard before re-POSTing. Context cancellation is never
// retried.
func isRetryableCreateError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var status runtime.ClientResponseStatus
	if errors.As(err, &status) {
		return status.IsCode(http.StatusTooManyRequests) || status.IsServerError()
	}
	return true // no HTTP status: transport/timeout, retryable behind the duplicate guard
}

// createErrorMayHaveCreated reports whether an error leaves open the possibility that the connection was
// created server-side. A 429 is rejected before processing, so it never creates a resource and is safe to
// retry without the list-by-name guard; a 5xx or a status-less transport error might have.
func createErrorMayHaveCreated(err error) bool {
	var status runtime.ClientResponseStatus
	if errors.As(err, &status) {
		return !status.IsCode(http.StatusTooManyRequests)
	}
	return true
}

// createRetryDelay returns the backoff for the given zero-based attempt: createRetryBaseDelay doubled per
// attempt, capped at createRetryMaxDelay.
func createRetryDelay(attempt int) time.Duration {
	d := createRetryBaseDelay << attempt
	if d <= 0 || d > createRetryMaxDelay { // d <= 0 guards against shift overflow
		return createRetryMaxDelay
	}
	return d
}

// createConnectionWithRetry POSTs the new connection and retries a bounded number of times on a transient
// 429/5xx (see the package note above). It returns the created connection's ID; a nil diagnostic means
// success.
func (r *ngsiemDataConnectionResource) createConnectionWithRetry(
	ctx context.Context,
	body *createDataConnectionBody,
	name string,
) (string, diag.Diagnostic) {
	// Baseline of same-named connection IDs, so a post-error list can distinguish a connection THIS call
	// created from a pre-existing or concurrently-created one. If the snapshot fails we can't safely dedup,
	// so the guard is disabled and a maybe-created error fails fast (a blind retry could duplicate).
	before, snapErr := r.connectionIDsByName(ctx, name)
	guardEnabled := snapErr == nil
	if snapErr != nil {
		tflog.Debug(ctx, "ngsiem create: name snapshot failed; retry-on-5xx guard disabled", map[string]interface{}{
			"name":  name,
			"error": snapErr.Error(),
		})
	}

	for attempt := 0; ; attempt++ {
		id, terminal, callErr := r.postConnectionOnce(ctx, body)
		if terminal != nil {
			return "", terminal // structural problem with a 2xx response: never retried
		}
		if callErr == nil {
			return id, nil
		}
		if !isRetryableCreateError(callErr) {
			return "", tferrors.NewDiagnosticFromAPIError(tferrors.Create, callErr, requiredScopes)
		}

		// A 5xx/transport error might have created the connection. Check before spending a retry —
		// re-POSTing an already-created connection is what produces a duplicate.
		if createErrorMayHaveCreated(callErr) {
			if !guardEnabled {
				return "", tferrors.NewDiagnosticFromAPIError(tferrors.Create, callErr, requiredScopes)
			}
			adoptedID, found, listErr := r.findCreatedConnection(ctx, before, name)
			if listErr != nil {
				// Couldn't confirm whether a connection was created; fail closed rather than risk a duplicate.
				return "", diag.NewErrorDiagnostic(
					fmt.Sprintf("Failed to %s", tferrors.Create),
					fmt.Sprintf("The create request failed with a transient error (%s) and the provider could not list "+
						"connections to check whether one was created anyway (%s). Re-run `terraform apply`; if a connection "+
						"named %q was created, import it or delete it in CrowdStrike first.", callErr.Error(), listErr.Error(), name),
				)
			}
			if found {
				tflog.Warn(ctx, "ngsiem create: POST returned a transient error but the connection was created server-side; adopting it", map[string]interface{}{
					"name":          name,
					"connection_id": adoptedID,
				})
				return adoptedID, nil
			}
		}

		if attempt >= maxCreateRetries {
			return "", tferrors.NewDiagnosticFromAPIError(tferrors.Create, callErr, requiredScopes)
		}
		tflog.Debug(ctx, "ngsiem create: transient error, retrying after backoff", map[string]interface{}{
			"name":    name,
			"attempt": attempt + 1,
			"error":   callErr.Error(),
		})
		select {
		case <-ctx.Done():
			return "", tferrors.NewDiagnosticFromAPIError(tferrors.Create, ctx.Err(), requiredScopes)
		case <-time.After(createRetryDelay(attempt)):
		}
	}
}

// postConnectionOnce performs a single create POST. It returns the new connection's ID on success, a
// terminal diagnostic for a 2xx response whose payload is structurally unusable (these are never
// retried), or callErr for a transport/HTTP-status failure (which the caller classifies for retry).
func (r *ngsiemDataConnectionResource) postConnectionOnce(
	ctx context.Context,
	body *createDataConnectionBody,
) (id string, terminal diag.Diagnostic, callErr error) {
	params := ngsiem.NewExternalCreateDataConnectionParams()
	params.Context = ctx

	res, err := r.client.Ngsiem.ExternalCreateDataConnection(params, func(op *runtime.ClientOperation) {
		op.Params = bodyOverrideParams{inner: op.Params, body: body}
	})
	if err != nil {
		return "", nil, err
	}
	if res == nil || res.Payload == nil {
		return "", tferrors.NewEmptyResponseError(tferrors.Create), nil
	}
	if d := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Create, res.Payload.Errors); d != nil {
		return "", d, nil
	}
	// Guard the ID itself: a 2xx with a nil/empty ID would persist an untrackable resource and poll the
	// token endpoint with ids="".
	if len(res.Payload.Resources) == 0 || res.Payload.Resources[0] == nil ||
		res.Payload.Resources[0].ID == nil || *res.Payload.Resources[0].ID == "" {
		return "", tferrors.NewEmptyResponseError(tferrors.Create), nil
	}
	return *res.Payload.Resources[0].ID, nil, nil
}

// connectionIDsByName returns the set of connection IDs whose name exactly equals name. The FQL `:`
// filter (exact match, vs the sweeper's `~` contains) narrows the result server-side; the name is
// re-checked client-side so a filter quirk can't widen the match.
func (r *ngsiemDataConnectionResource) connectionIDsByName(ctx context.Context, name string) (map[string]struct{}, error) {
	params := ngsiem.NewExternalListDataConnectionsParams()
	params.Context = ctx
	limit := connectionPageSize
	params.Limit = &limit
	params.Filter = utils.Addr(fmt.Sprintf("name:'%s'", name))

	res, err := r.client.Ngsiem.ExternalListDataConnections(params)
	if err != nil {
		return nil, err
	}
	if res == nil || res.Payload == nil {
		return map[string]struct{}{}, nil
	}
	if d := tferrors.NewDiagnosticFromPayloadErrors(tferrors.Read, res.Payload.Errors); d != nil {
		return nil, fmt.Errorf("%s: %s", d.Summary(), d.Detail())
	}
	ids := make(map[string]struct{}, len(res.Payload.Resources))
	for _, c := range res.Payload.Resources {
		if c == nil || c.ID == nil || c.Name == nil || *c.ID == "" {
			continue
		}
		if *c.Name == name {
			ids[*c.ID] = struct{}{}
		}
	}
	return ids, nil
}

// findCreatedConnection lists same-named connections after a transient create error and reports whether
// exactly one NEW one (absent from before) appeared — i.e. the POST created it server-side despite the
// error, so it should be adopted rather than re-POSTed. Zero new → nothing was created (safe to retry).
// More than one new → ambiguous (concurrent same-name creates); returned as an error so the caller fails
// closed rather than adopt the wrong connection.
func (r *ngsiemDataConnectionResource) findCreatedConnection(
	ctx context.Context,
	before map[string]struct{},
	name string,
) (string, bool, error) {
	after, err := r.connectionIDsByName(ctx, name)
	if err != nil {
		return "", false, err
	}
	created := newConnectionIDs(before, after)
	switch len(created) {
	case 0:
		return "", false, nil
	case 1:
		return created[0], true, nil
	default:
		return "", false, fmt.Errorf(
			"found %d new connections named %q after a transient create error; cannot determine which one belongs to this resource",
			len(created), name,
		)
	}
}

// newConnectionIDs returns the IDs present in after but not in before.
func newConnectionIDs(before, after map[string]struct{}) []string {
	var out []string
	for id := range after {
		if _, existed := before[id]; !existed {
			out = append(out, id)
		}
	}
	return out
}

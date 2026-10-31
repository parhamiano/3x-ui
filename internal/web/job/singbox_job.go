package job

import (
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/singbox"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

// SingboxJob converges the sing-box sidecars on the enabled AnyTLS inbounds and
// restarts any that crashed; their traffic is billed by Xray's relay inbound.
type SingboxJob struct {
	inboundService service.InboundService
}

func NewSingboxJob() *SingboxJob {
	return new(SingboxJob)
}

func (j *SingboxJob) Run() {
	desired, err := j.inboundService.DesiredSingboxInstances()
	if err != nil {
		logger.Warning("singbox job: get desired instances failed:", err)
		return
	}
	singbox.GetManager().Reconcile(desired)
}

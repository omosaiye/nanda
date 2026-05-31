package agentfacts

const (
	EndpointTypeStatic           = "static"
	EndpointTypeRotating         = "rotating"
	EndpointTypeAdaptiveResolver = "adaptiveResolver"
)

type Endpoint struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	URL        string `json:"url"`
	Protocol   string `json:"protocol"`
	TTLSeconds uint16 `json:"ttlSeconds"`
}

package main

// cfg holds runtime configuration, loaded once from environment
// variables at startup.
type cfg struct {
	ListenAddr          string
	OrdersURL           string
	InventoryURL        string
	Auth0Domain         string
	Auth0ClientID       string
	Auth0ClientSecret   string
	PublicURL           string
	SessionSecret       string
	StripeSecretKey     string
	StripeWebhookSecret string
}

func loadConfig() cfg {
	return cfg{
		ListenAddr:          envOr("LISTEN_ADDR", ":9090"),
		OrdersURL:           mustEnv("ORDERS_URL"),
		InventoryURL:        mustEnv("INVENTORY_URL"),
		Auth0Domain:         envOr("AUTH0_DOMAIN", ""),
		Auth0ClientID:       envOr("AUTH0_CLIENT_ID", ""),
		Auth0ClientSecret:   envOr("AUTH0_CLIENT_SECRET", ""),
		PublicURL:           envOr("PUBLIC_URL", ""),
		SessionSecret:       envOr("SESSION_SECRET", ""),
		StripeSecretKey:     envOr("STRIPE_SECRET_KEY", ""),
		StripeWebhookSecret: envOr("STRIPE_WEBHOOK_SECRET", ""),
	}
}

package limiter

type IPLimit struct {
	Enable          bool   `mapstructure:"Enable"`
	RedisNetwork    string `mapstructure:"RedisNetwork"` // tcp or unix
	RedisAddr       string `mapstructure:"RedisAddr"`    // host:port, or /path/to/unix.sock
	RedisUsername   string `mapstructure:"RedisUsername"`
	RedisPassword   string `mapstructure:"RedisPassword"`
	RedisDB         int    `mapstructure:"RedisDB"`
	Timeout         int    `mapstructure:"Timeout"`
	Expiry          int    `mapstructure:"Expiry"`  // second
	Scope           string `mapstructure:"Scope"`   // shared panel/tenant namespace, never an inbound tag
	OnError         string `mapstructure:"OnError"` // allow (default) or deny; authentication remains mandatory
	RedisTLS        bool   `mapstructure:"RedisTLS"`
	RedisServerName string `mapstructure:"RedisServerName"`
}

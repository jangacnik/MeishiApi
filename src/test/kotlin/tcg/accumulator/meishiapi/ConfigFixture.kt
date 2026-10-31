package tcg.accumulator.meishiapi

fun testConfig(
    httpPort: Int = 0,
    dbHost: String = "localhost",
    dbPort: Int = 5432,
    dbName: String = "meishi",
    dbUser: String = "meishi",
    dbPassword: String = "meishi",
    dbConnectTimeoutMillis: Int = 5000,
    dbSslMode: String? = null,
) = AppConfig(
    httpPort = httpPort,
    dbHost = dbHost,
    dbPort = dbPort,
    dbName = dbName,
    dbUser = dbUser,
    dbPassword = dbPassword,
    dbPoolSize = 2,
    dbConnectTimeoutMillis = dbConnectTimeoutMillis,
    dbSslMode = dbSslMode,
    migrationUser = dbUser,
    migrationPassword = dbPassword,
    jwtSecret = "test-secret-with-at-least-32-bytes!!",
    adminNickname = "admin",
    adminPassword = "admin-pass-for-tests",
)

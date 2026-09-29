import os


class Settings:
    POSTGRES_HOST = os.getenv("POSTGRES_HOST", "db")
    POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
    POSTGRES_DB = os.getenv("POSTGRES_DB", "nullbait_db")
    POSTGRES_USER = os.getenv("POSTGRES_USER", "nullbait_user")
    POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "nullbait_secret_2024")

    SECRET_KEY = os.getenv("SECRET_KEY", "change_this_later")
    ALGORITHM = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

    CRITICAL_THREAT_SCORE = int(os.getenv("CRITICAL_THREAT_SCORE", 75))

    DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "admin")
    DASHBOARD_PASSWORD_HASH = os.getenv("DASHBOARD_PASSWORD_HASH", "")

    # the actual origin your frontend is served from — used to lock down CORS
    FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://10.10.1.141:3000")

    @property
    def database_url(self) -> str:
        return (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )


settings = Settings()

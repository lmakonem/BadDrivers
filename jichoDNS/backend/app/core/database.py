"""Database connection and session management."""

from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)
from sqlalchemy.pool import NullPool

from app.core.config import settings


# Convert postgresql:// to postgresql+asyncpg://
database_url = str(settings.DATABASE_URL)
if database_url.startswith("postgresql://"):
    database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)


def build_engine(*, use_pool: bool = True) -> AsyncEngine:
    """
    Build the async SQLAlchemy engine.

    use_pool=True (default): a real connection pool. create_async_engine
        transparently substitutes AsyncAdaptedQueuePool (the asyncio-safe
        QueuePool). Correct for the FastAPI process, which serves every request
        on one long-lived event loop, so pooled asyncpg connections stay bound
        to a live loop. pool_pre_ping validates a connection before handing it
        out; pool_recycle caps connection age.

    use_pool=False: NullPool — no connection is retained between checkouts.
        Required for Celery workers, which run each task in a fresh event loop
        (see app.worker.run_async). A retained pool would hand a later task an
        asyncpg connection bound to an already-closed loop and raise
        "got Future attached to a different loop".
    """
    if use_pool:
        return create_async_engine(
            database_url,
            pool_size=settings.DB_POOL_SIZE,
            max_overflow=settings.DB_MAX_OVERFLOW,
            pool_pre_ping=True,
            pool_recycle=settings.DB_POOL_RECYCLE,
            echo=settings.LOG_LEVEL == "DEBUG",
        )
    return create_async_engine(
        database_url,
        poolclass=NullPool,
        echo=settings.LOG_LEVEL == "DEBUG",
    )


# API default: pooled engine bound to the uvicorn event loop.
engine: AsyncEngine = build_engine(use_pool=True)

# Session factory (rebound by configure_for_worker() inside Celery children)
async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


def configure_for_worker() -> None:
    """
    Rebind the module-level engine/session factory to a NullPool engine.

    Call exactly once per Celery worker child process (from a
    worker_process_init handler) BEFORE any task runs. Worker tasks import
    async_session_maker lazily inside the task body, so they pick up this
    rebind. See build_engine() for why workers must not pool.
    """
    global engine, async_session_maker
    try:
        # Abandon (do not close) any pool connections inherited across fork.
        engine.sync_engine.dispose(close=False)
    except Exception:
        pass
    engine = build_engine(use_pool=False)
    async_session_maker = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )


async def get_db() -> AsyncSession:
    """
    Dependency that yields a database session.
    
    Usage in FastAPI:
        @app.get("/items")
        async def get_items(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Initialize database - create all tables."""
    from app.models import Base
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db():
    """Close database connections."""
    await engine.dispose()

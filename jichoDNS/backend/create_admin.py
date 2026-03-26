#!/usr/bin/env python3
"""
Create the first admin user.

Usage:
    docker exec jichodns-api python create_admin.py <email> <password> [--name "Admin Name"]
"""

import asyncio
import sys
from sqlalchemy import select

async def main():
    if len(sys.argv) < 3:
        print("Usage: python create_admin.py <email> <password> [--name 'Name']")
        sys.exit(1)

    email = sys.argv[1]
    password = sys.argv[2]
    name = "Admin"

    for i, arg in enumerate(sys.argv):
        if arg == "--name" and i + 1 < len(sys.argv):
            name = sys.argv[i + 1]

    from app.core.database import async_session_maker, init_db
    from app.core.security import hash_password
    from app.models.user import User

    await init_db()

    async with async_session_maker() as session:
        result = await session.execute(select(User).where(User.email == email))
        existing = result.scalar_one_or_none()

        if existing:
            existing.is_admin = True
            existing.is_active = True
            existing.is_verified = True
            if password:
                existing.hashed_password = hash_password(password)
            await session.commit()
            print(f"User {email} promoted to admin.")
        else:
            user = User(
                email=email,
                hashed_password=hash_password(password),
                name=name,
                is_active=True,
                is_verified=True,
                is_admin=True,
                tier="enterprise",
                daily_api_limit=999999,
                monthly_api_limit=999999,
            )
            session.add(user)
            await session.commit()
            print(f"Admin user {email} created.")

asyncio.run(main())

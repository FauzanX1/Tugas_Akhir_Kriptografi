"""
SecureVault - Database Manager
Handles MySQL connection pooling, query execution with prepared statements,
and automatic schema migration.
"""

import mysql.connector
from mysql.connector import Error, pooling
from config.settings import DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME, BASE_DIR

class DatabaseManager:
    _instance = None
    _pool = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
            cls._instance._init_database()
        return cls._instance

    def _init_database(self):
        """Ensure database exists and create tables from schema.sql."""
        try:
            # 1. Connect without database name to create database if not exists
            server_conn = mysql.connector.connect(
                host=DB_HOST,
                port=DB_PORT,
                user=DB_USER,
                password=DB_PASSWORD
            )
            cursor = server_conn.cursor()
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
            cursor.close()
            server_conn.close()

            # 2. Setup Connection Pool
            self._pool = pooling.MySQLConnectionPool(
                pool_name="securevault_pool",
                pool_size=5,
                host=DB_HOST,
                port=DB_PORT,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME
            )

            # 3. Apply schema.sql
            schema_file = BASE_DIR / "database" / "schema.sql"
            if schema_file.exists():
                with open(schema_file, "r", encoding="utf-8") as f:
                    schema_sql = f.read()
                
                with self.get_connection() as conn:
                    with conn.cursor() as cur:
                        for statement in schema_sql.split(";"):
                            stmt = statement.strip()
                            if stmt:
                                cur.execute(stmt)
                    conn.commit()

        except Error as e:
            print(f"[DatabaseManager Error] Initialization failed: {e}")
            raise e

    def get_connection(self):
        """Retrieve a connection from the pool."""
        if not self._pool:
            self._init_database()
        return self._pool.get_connection()

    def execute_query(self, query: str, params: tuple = None) -> int:
        """Execute INSERT, UPDATE, or DELETE query and return affected rows."""
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(query, params or ())
                conn.commit()
                return cursor.rowcount
        finally:
            conn.close()

    def insert_get_id(self, query: str, params: tuple = None) -> int:
        """Execute INSERT and return the generated lastrowid."""
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(query, params or ())
                conn.commit()
                return cursor.lastrowid
        finally:
            conn.close()

    def fetch_one(self, query: str, params: tuple = None) -> dict | None:
        """Fetch a single record as dictionary."""
        conn = self.get_connection()
        try:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute(query, params or ())
                return cursor.fetchone()
        finally:
            conn.close()

    def fetch_all(self, query: str, params: tuple = None) -> list[dict]:
        """Fetch all records as a list of dictionaries."""
        conn = self.get_connection()
        try:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute(query, params or ())
                return cursor.fetchall()
        finally:
            conn.close()

    def check_connection(self) -> bool:
        """Verify if MySQL database is reachable."""
        try:
            conn = self.get_connection()
            alive = conn.is_connected()
            conn.close()
            return alive
        except Exception:
            return False

# Global database helper instance
db = DatabaseManager()

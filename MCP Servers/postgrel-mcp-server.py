import logging
from mcp.server.lowlevel import Server
import os
from mcp.server.sse import SseServerTransport
from typing import (Any, Generator, List, Optional, Tuple, TypedDict, Sequence)
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from enum import Enum
from dotenv import load_dotenv
from taosrest import RestClient
from mcp.types import Tool, TextContent
import json
import uuid
import redis
import pandas as pd

logger = logging.getLogger(__name__)

load_dotenv()

# ========================
# 新增：Redis 配置
# ========================
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
REDIS_DB = int(os.getenv("REDIS_DB", 0))
RESULT_TTL = int(os.getenv("RESULT_TTL", 3600))  # 默认 1 小时

redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password= REDIS_PASSWORD,
    db=REDIS_DB,
    decode_responses=False  # 关键！避免 JSON 字节被错误解码
)

class TdengineTools(str, Enum):
    QUERY_TAOS_DB_DATA = "query_taos_db_data"
    GET_ALL_STABLES = "get_all_stables"
    SWITCH__DB = "switch_db"
    GET_FILED_INFO = "get_filed_info"
    GET_CACHED_RESULT = "get_cached_result"  # 新增工具

NOT_ALLOWED_TAOS_SQL: Tuple = (
    "ALTER", "CREATE", "DELETE", "DROP", "INSERT", "UPDATE", "TRIM", "FLUSH",
    "BALANCE", "REDISTRIBUTE", "GRANT", "REVOKE", "RESET", "KILL", "COMPACT",
)

class TaosSqlResponse(TypedDict):
    status: str
    head: List[str]
    column_meta: List[List[str | int]]
    data: List[List[Any]]
    rows: int

class TAOSClient:
    def __init__(
        self,
        *,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
        timeout: int = 30,
    ) -> None:
        self.host = host or os.getenv('TAOS_HOST')
        self.port = port or (os.getenv('TAOS_PORT') and int(os.getenv('TAOS_PORT')))
        self.username = username or os.getenv('TAOS_USERNAME')
        self.password = password or os.getenv('TAOS_PASSWORD')
        self.database = database or os.getenv('TAOS_DATABASE')
        self.timeout = timeout
        self.client: RestClient = next(self.init_db())

    def init_db(self) -> Generator[RestClient, None, None]:
        _url = f"http://{self.host}:{self.port}"
        try:
            client = RestClient(
                url=_url,
                user=self.username,
                password=self.password,
                database=self.database,
                timeout=self.timeout,
            )
            logger.info("Have initialized the taos client.")
            yield client
        except Exception as e:
            logger.error(f"Failed to connect to taos db => url: {_url}")
            raise e

    def execute_sql(self, sql_stmt: str) -> TaosSqlResponse:
        """Execute SQL query and return the result."""        

        logger.debug(f"Received TaosSQL statement: {sql_stmt}")
        validate_sql_stmt(sql_stmt)
        try:
            result = self.client.sql(sql_stmt)
            return TaosSqlResponse(
                status=result.get("status", ""),
                head=result.get("head", []),
                column_meta=result.get("column_meta", []),
                data=result.get("data", []),
                rows=result.get("rows", -1),
            )
        except Exception as e:
            logger.error(f"Failed to execute SQL: {sql_stmt}")
            raise e

def validate_sql_stmt(sql_stmt: str):
    """Check if the SQL statement is allowed."""

    logger.debug(f"Received TaosSQL statement: {sql_stmt}")
    sql_stmt = sql_stmt.strip()
    if sql_stmt.upper().startswith(NOT_ALLOWED_TAOS_SQL):
        logger.warning(f"Only isReadOnly statements are allowed. Received: {sql_stmt}")
        raise ValueError(
            "Security restrictions: Only read-only statements such as queries are allowed to be executed. All other operations are prohibited."
        )


Taos_client = TAOSClient()

# ========================
# 新增：缓存管理函数
# ========================
def extract_column_names(result: TaosSqlResponse) -> List[str]:
    if result["head"]:
        return result["head"]
    if result["column_meta"]:
        return [meta[0] for meta in result["column_meta"]]
    return [f"col_{i}" for i in range(len(result["data"][0]))] if result["data"] else []

def save_result_to_redis(head: List[str], data: List[List[Any]], rows: int) -> str:
    """将查询结果存入 Redis，返回 result_id"""
    result_id = f"res_{uuid.uuid4().hex[:8]}"
    key = result_id

    # 构造 DataFrame 并序列化为 JSON
    df = pd.DataFrame(data, columns=head)
    json_bytes = df.to_json(orient='records', date_format='iso').encode('utf-8')

    redis_client.setex(key, RESULT_TTL, json_bytes)
    return result_id


# ========================
# 修改：Tdengine_mcp_server
# ========================
class Tdengine_mcp_server:
    def query_taos_db_data(self, sql_stmt: str) -> dict:
        result = Taos_client.execute_sql(sql_stmt)
    
        # ✅ 正确提取列名
        head = extract_column_names(result)
    
        result_id = save_result_to_redis(
            head=head,
            data=result["data"],
            rows=result["rows"]
         )
        return {
            "cached": True,
            "result_id": result_id,
            "rows": result["rows"],
            "message": f"Use get_cached_result with result_id={result_id}"
        }

    # 其他方法保持不变（因为结果小）
    def get_all_stables(
            self,
            db_name: str

         ) -> TaosSqlResponse:
            """Get all stables.

            Args:
                db_name (Optional[str]): The name of the database. Defaults to None. When the value is None, it means the configured database is used.

            Returns:
                TaosSqlResponse: All stables in the current Taos database.
            """
            if db_name is None or db_name == "":
               db_name = Taos_client.database
            
            result = Taos_client.execute_sql(f"SHOW {db_name}.STABLES;")
            return result
    
    def switch_db(
            self,
            db_name: str

         ) ->TaosSqlResponse:
            """Switch to the specified database.

            Args:
                db_name (str): The name of the database to switch to.

            Returns:
                TaosSqlResponse: The result of the `USE` command.
            """
            result = Taos_client.execute_sql(f"USE {db_name};")
            return result
    
    def get_filed_info(
            self,
            db_name:str,

            stable_name:str
          ) ->TaosSqlResponse:
            """Get the field information of the specified stable.

            Args:
                db_name (Optional[str]): The name of the database. Defaults to None. When the value is None, it means the configured database is used.
                stable_name (str): The name of the stable.

            Returns:
                TaosSqlResponse: The field information of the specified stable.
            """
            result = Taos_client.execute_sql(f"DESCRIBE {db_name}.{stable_name};")
            return result

# ========================
# 更新：工具注册
# ========================
app = Server("Tdengine_tools")
td_mcp = Tdengine_mcp_server()
sse = SseServerTransport("/messages/")

@app.list_tools()
async def handle_list_tools() -> List[Tool]:
    return [
        Tool(
            name=TdengineTools.QUERY_TAOS_DB_DATA.value,
            description="Run a read-only SQL query on TDengine. Large results will be cached and return a result_id.",
            inputSchema={
                "type": "object",
                "properties": {
                    "sql_stmt": {
                        "type": "string",
                        "description": "The sql statement you want to retrieve data from taos db.",
                    }
                },
                "required": ["sql_stmt"],
            },
        ),
        Tool(
            name = "get_all_dbs",
            description="List all dbs in the Tdengine database",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name = TdengineTools.GET_ALL_STABLES.value,
            description="List all stables in the specific db.",
            inputSchema={
                "type": "object",
                "properties": {
                    "db_name": {
                        "type": "string",
                        "description": "The name of database.",
                    }
                },
                "required": ["db_name"],
                 
            },
        ),
        Tool(
            name = TdengineTools.SWITCH__DB.value,
            description="Switch to the specified database.",
            inputSchema={
                "type": "object",
                "properties": {
                    "db_name": {
                        "type": "string",
                        "description": "The name of database.",
                    }
                },
                "required": ["db_name"],
                 
            },
        ),
        Tool(
            name = TdengineTools.GET_FILED_INFO.value,
            description="Get the field information of the specified stable.",
            inputSchema={
                "type": "object",
                "properties": {
                    "db_name": {
                        "type": "string",
                        "description": "The name of database.",
                    },
                    "stable_name":{
                         
                         "type": "string",
                         "description": "The name of the stable"
                    },
                },
                "required": ["db_name","stable_name"],
                 
            },
        ),

        ]

# ========================
# 更新：工具调用处理
# ========================
@app.call_tool()
async def handle_call_tool(
    name: str, arguments: dict
) -> Sequence[TextContent]:
    """Handle tool calls for Tdengine queries."""
    try:
        match name:
            case TdengineTools.QUERY_TAOS_DB_DATA.value:
                sql_stmt = arguments.get("sql_stmt")
                if not sql_stmt:
                    raise ValueError("Missing required argument: sql_stmt")
                result = td_mcp.query_taos_db_data(sql_stmt)
            
            case TdengineTools.GET_ALL_STABLES.value:
                db_name = arguments.get("db_name")
                if not db_name:
                    raise ValueError("Missing required argument: db_name")
                result = td_mcp.get_all_stables(db_name)

            case TdengineTools.SWITCH__DB.value:
                db_name = arguments.get("db_name")
                if not db_name:
                    raise ValueError("Missing required argument: db_name")
                result = td_mcp.switch_db(db_name)

            case TdengineTools.GET_FILED_INFO.value:
                if not all(
                    k in arguments
                    for k in ["db_name","stable_name"]
                ):
                    raise ValueError("Missing required arguments")
                result = td_mcp.get_filed_info(
                    arguments["db_name"],
                    arguments["stable_name"],
                )
            case "get_all_dbs":
                result = td_mcp.query_taos_db_data("SHOW DATABASES;")


            case _:
                raise ValueError(f"Unknown tool: {name}")

        return [
            TextContent(type="text", text=json.dumps(result, indent=2))
        ]
    except Exception as e:
        raise ValueError(f"Error processing Tdengine query: {str(e)}")

# ========================
# 不变：Starlette App
# ========================
async def handle_sse(request):
    async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
        await app.run(streams[0], streams[1], app.create_initialization_options())

starlette_app = Starlette(
    debug=True,
    routes=[
        Route("/sse", endpoint=handle_sse),
        Mount("/messages/", app=sse.handle_post_message),
    ]
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(starlette_app, host="0.0.0.0", port=8002)

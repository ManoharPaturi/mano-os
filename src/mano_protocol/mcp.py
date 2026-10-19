"""Pinned MCP metadata discovery; descriptions and schemas never grant authority."""

import hashlib
import json
import re

from .actions import canonical, text, unique_object

VERSION = "2026-07-28"
LINE_LIMIT = 32768
WIRE_LIMIT = 65536
TOOLS_LIMIT = 32
PAGES_LIMIT = 4
MESSAGE_LIMIT = 64
META_PREFIX = "io.modelcontextprotocol/"


def tree(value):
    stack, count = [(value, 0)], 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > 2048 or depth > 16:
            raise ValueError("MCP metadata structure exceeds budget")
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise ValueError("MCP metadata keys must be strings")
            for key, child in item.items():
                if key in {"$ref", "$dynamicRef", "$recursiveRef"}:
                    if not isinstance(child, str) or not child.startswith("#"):
                        raise ValueError("External MCP schema references are unsupported")
                stack.append((child, depth + 1))
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            if len(item.encode()) > 8192:
                raise ValueError("MCP metadata string exceeds budget")
        elif item is not None and type(item) not in {bool, int, float}:
            raise ValueError("Unsupported MCP metadata value")
    # Reject nonfinite numbers even when this validator is called in-process.
    canonical(value)


def decode(packet):
    if not isinstance(packet, bytes) or not 1 <= len(packet) <= LINE_LIMIT:
        raise ValueError("Bounded MCP JSON line required")
    try:
        value = json.loads(
            packet.decode("utf8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite MCP number")),
        )
    except RecursionError as error:
        raise ValueError("MCP JSON nesting exceeds parser budget") from error
    tree(value)
    return value


def tool(value):
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import SchemaError

    if (
        not isinstance(value, dict)
        or not isinstance(value.get("name"), str)
        or not re.fullmatch(r"[A-Za-z0-9_./:-]{1,128}", value["name"])
        or not isinstance(value.get("inputSchema"), dict)
    ):
        raise ValueError("Invalid bounded MCP tool descriptor")
    tree(value)
    if "description" in value:
        text(value["description"], 4096, allow_empty=True)
    for key in ("inputSchema", "outputSchema"):
        if key not in value:
            continue
        schema = value[key]
        if (
            not isinstance(schema, dict)
            or schema.get("type") != "object"
            or schema.get("$schema", "https://json-schema.org/draft/2020-12/schema")
            not in {
                "https://json-schema.org/draft/2020-12/schema",
                "https://json-schema.org/draft/2020-12/schema#",
            }
        ):
            raise ValueError("MCP discovery requires JSON Schema 2020-12 objects")
        # Metaschema validation uses the validator's bundled schema. No network
        # schema resolution or executable tool implementation is performed.
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as error:
            raise ValueError("Invalid MCP JSON Schema") from error
    return value


def request(method, request_id, *, cursor=None):
    if method not in {"server/discover", "tools/list"}:
        raise ValueError("Only MCP metadata requests are supported")
    text(request_id, 64)
    params = {
        "_meta": {
            META_PREFIX + "protocolVersion": VERSION,
            META_PREFIX + "clientInfo": dict(name="mano-os", version="0.1.0"),
            META_PREFIX + "clientCapabilities": {},
        }
    }
    if cursor is not None:
        if method != "tools/list":
            raise ValueError("Only tool lists can have a cursor")
        params["cursor"] = text(cursor, 512)
    return canonical(dict(jsonrpc="2.0", id=request_id, method=method, params=params)) + "\n"


class Discovery:
    """One process, explicit modern version, no era probing/fallback or tool calls."""

    def __init__(self):
        self.expected_id = "mano-discover"
        self.next_packet = request("server/discover", self.expected_id).encode()
        self.server = None
        self.tools = []
        self.cursors = set()
        self.pages = self.messages = self.wire_bytes = 0
        self.digest = hashlib.sha256()
        self.done = False
        self.awaiting = False

    def sent(self):
        if self.awaiting or self.done or self.next_packet is not None:
            raise ValueError("Only a fully delivered pending MCP request can await a response")
        self.awaiting = True

    def accept(self, line):
        self.messages += 1
        self.wire_bytes += len(line) + 1
        if self.messages > MESSAGE_LIMIT or self.wire_bytes > WIRE_LIMIT:
            raise ValueError("MCP discovery wire quota exhausted")
        self.digest.update(line + b"\n")
        value = decode(line)
        if not isinstance(value, dict) or value.get("jsonrpc") != "2.0":
            raise ValueError("Invalid MCP JSON-RPC envelope")
        if "id" not in value and isinstance(value.get("method"), str):
            if (
                set(value) - {"jsonrpc", "method", "params"}
                or not value["method"].startswith("notifications/")
                or ("params" in value and not isinstance(value["params"], dict))
            ):
                raise ValueError("Unsupported MCP server notification")
            return  # Bounded untrusted notifications do not trigger callbacks.
        if (
            not self.awaiting
            or self.done
            or set(value) - {"jsonrpc", "id", "result", "error"}
            or type(value.get("id")) is not str
            or value["id"] != self.expected_id
            or ("result" in value) == ("error" in value)
        ):
            raise ValueError("Unbound or unsolicited MCP response/request")
        self.awaiting = False
        if "error" in value:
            raise ValueError("MCP peer rejected metadata request; no automatic retry")
        result = value["result"]
        if not isinstance(result, dict) or result.get("resultType", "complete") != "complete":
            raise ValueError("MCP discovery does not authorize interactive input or callbacks")
        if self.server is None:
            versions = result.get("supportedVersions")
            caps = result.get("capabilities")
            if (
                not isinstance(versions, list)
                or len(versions) > 16
                or any(not isinstance(version, str) for version in versions)
                or VERSION not in versions
                or not isinstance(caps, dict)
            ):
                raise ValueError("MCP server does not support approved protocol revision")
            self.server = result
            if "tools" not in caps:
                self.done = True
                return
            if not isinstance(caps["tools"], dict):
                raise ValueError("Invalid MCP tools capability")
        else:
            values = result.get("tools")
            if not isinstance(values, list) or len(self.tools) + len(values) > TOOLS_LIMIT:
                raise ValueError("MCP tools exceed discovery budget")
            names = {item["name"] for item in self.tools}
            for item in values:
                tool(item)
                if item["name"] in names:
                    raise ValueError("Duplicate MCP tool identity")
                names.add(item["name"])
                self.tools.append(item)
            cursor = result.get("nextCursor")
            if cursor is None:
                self.done = True
                return
            text(cursor, 512)
            if cursor in self.cursors:
                raise ValueError("Repeated MCP pagination cursor")
            self.cursors.add(cursor)
        self.pages += 1
        if self.pages > PAGES_LIMIT:
            raise ValueError("MCP tool pagination exhausted")
        self.expected_id = "mano-tools-" + str(self.pages)
        cursor = None if self.pages == 1 else cursor
        self.next_packet = request("tools/list", self.expected_id, cursor=cursor).encode()

    def manifest(self, *, server_return_code):
        if not self.done or server_return_code != 0:
            raise ValueError("No complete successful MCP metadata operation")
        value = dict(
            schema_version="1.0",
            protocol_version=VERSION,
            server_claims=self.server,
            tools=[
                dict(descriptor=item, untrusted=True, invocation_authorized=False)
                for item in self.tools
            ],
            wire_sha256=self.digest.hexdigest(),
            messages=self.messages,
            server_return_code=server_return_code,
            untrusted=True,
            invocation_authorized=False,
        )
        if len(canonical(value).encode()) > WIRE_LIMIT:
            raise ValueError("MCP manifest exceeds custody budget")
        manifest(value)
        return value


def manifest(value):
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema_version",
            "protocol_version",
            "server_claims",
            "tools",
            "wire_sha256",
            "messages",
            "server_return_code",
            "untrusted",
            "invocation_authorized",
        }
        or value["schema_version"] != "1.0"
        or value["protocol_version"] != VERSION
        or value["server_return_code"] != 0
        or type(value["server_return_code"]) is not int
        or value["untrusted"] is not True
        or value["invocation_authorized"] is not False
        or not isinstance(value["server_claims"], dict)
        or not isinstance(value["tools"], list)
        or len(value["tools"]) > TOOLS_LIMIT
        or type(value["messages"]) is not int
        or not 1 <= value["messages"] <= MESSAGE_LIMIT
        or not isinstance(value["wire_sha256"], str)
        or not re.fullmatch("[0-9a-f]{64}", value["wire_sha256"])
    ):
        raise ValueError("Invalid untrusted MCP discovery manifest")
    tree(value)
    claims = value["server_claims"]
    versions = claims.get("supportedVersions")
    if (
        not isinstance(versions, list)
        or VERSION not in versions
        or len(versions) > 16
        or any(not isinstance(version, str) for version in versions)
        or not isinstance(claims.get("capabilities"), dict)
        or claims.get("resultType", "complete") != "complete"
        or (value["tools"] and not isinstance(claims["capabilities"].get("tools"), dict))
    ):
        raise ValueError("Invalid MCP server discovery claims")
    names = set()
    for entry in value["tools"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"descriptor", "untrusted", "invocation_authorized"}
            or entry["untrusted"] is not True
            or entry["invocation_authorized"] is not False
        ):
            raise ValueError("MCP descriptor cannot carry authority")
        item = tool(entry["descriptor"])
        if item["name"] in names:
            raise ValueError("Duplicate manifest MCP tool")
        names.add(item["name"])
    return value

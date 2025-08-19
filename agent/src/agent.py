import json
from typing import Any, Generator
from uuid import uuid4

import mlflow
from databricks_langchain import ChatDatabricks
from langchain_core.messages import AIMessage, AIMessageChunk
from mlflow.entities import SpanType
from mlflow.pyfunc import ResponsesAgent
from mlflow.types.responses import (
    ResponsesAgentRequest,
    ResponsesAgentResponse,
    ResponsesAgentStreamEvent,
)

# Define the LLM endpoint
LLM_ENDPOINT_NAME = "databricks-claude-3-7-sonnet"
llm = ChatDatabricks(endpoint=LLM_ENDPOINT_NAME)

# Simple system prompt
system_prompt = "You are a helpful assistant."


class SimpleChatAgent(ResponsesAgent):
    def __init__(self):
        self.llm = llm
        self.system_prompt = system_prompt

    def _responses_to_cc(self, message: dict[str, Any]) -> list[dict[str, Any]]:
        """Convert from a Responses API output item to ChatCompletion messages."""
        msg_type = message.get("type")
        if msg_type == "message" and isinstance(message["content"], list):
            return [
                {"role": message["role"], "content": content["text"]}
                for content in message["content"]
            ]
        elif msg_type == "message":
            return [{"role": message["role"], "content": message["content"]}]
        
        # Handle other message types
        compatible_keys = ["role", "content", "name"]
        filtered = {k: v for k, v in message.items() if k in compatible_keys}
        return [filtered] if filtered else []

    def _langchain_to_responses(self, message: dict[str, Any]) -> list[dict[str, Any]]:
        """Convert from ChatCompletion dict to Responses output item dictionaries"""
        role = message.get("type", "ai")
        if role == "ai":
            return [
                self.create_text_output_item(
                    text=message["content"],
                    id=message.get("id") or str(uuid4()),
                )
            ]
        elif role == "user":
            return [message]
        return []

    def predict(self, request: ResponsesAgentRequest) -> ResponsesAgentResponse:
        outputs = [
            event.item
            for event in self.predict_stream(request)
            if event.type == "response.output_item.done"
        ]
        return ResponsesAgentResponse(output=outputs, custom_outputs=request.custom_inputs)

    def predict_stream(
        self,
        request: ResponsesAgentRequest,
    ) -> Generator[ResponsesAgentStreamEvent, None, None]:
        # Log custom inputs if present
        if request.custom_inputs:
            print(f"Custom inputs received: {json.dumps(request.custom_inputs, indent=2)}")
            # You could also log to MLflow here if needed
            # mlflow.log_dict(request.custom_inputs, "custom_inputs.json")

        # Convert request messages to ChatCompletion format
        cc_msgs = []
        for msg in request.input:
            cc_msgs.extend(self._responses_to_cc(msg.model_dump()))

        # Add system prompt if messages exist
        if cc_msgs:
            cc_msgs = [{"role": "system", "content": self.system_prompt}] + cc_msgs

        # Stream the response from the LLM
        for chunk in self.llm.stream(cc_msgs):
            if isinstance(chunk, AIMessageChunk) and (content := chunk.content):
                yield ResponsesAgentStreamEvent(
                    **self.create_text_delta(delta=content, item_id=chunk.id),
                )


# Create the agent object and set it for MLflow
mlflow.langchain.autolog()
AGENT = SimpleChatAgent()
mlflow.models.set_model(AGENT)

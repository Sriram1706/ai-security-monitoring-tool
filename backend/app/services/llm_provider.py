import httpx

from app.config import settings


async def generate_openai_response(prompt: str) -> str:
    if not settings.openai_api_key:
        return "OpenAI API key not configured."

    url = f"{settings.openai_base_url}/responses"
    headers = {
        "Authorization": f"Bearer {settings.openai_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": settings.openai_model,
        "input": prompt,
    }
    async with httpx.AsyncClient(timeout=30) as client:
        res = await client.post(url, headers=headers, json=payload)
        res.raise_for_status()
        data = res.json()
        if "output_text" in data:
            return data["output_text"] or ""
        output = data.get("output", [])
        for item in output:
            for content in item.get("content", []):
                if content.get("type") == "output_text":
                    return content.get("text", "")
        return ""

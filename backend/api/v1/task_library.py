"""Task library API — CRUD endpoints for pentesting task templates."""

import uuid
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.core.task_library import Task, get_task_library

router = APIRouter()


class TaskResponse(BaseModel):
    """Task from library."""
    id: str
    name: str
    description: str
    category: str
    prompt: str
    tags: List[str]
    is_preset: bool
    estimated_tokens: int


class CreateTaskRequest(BaseModel):
    """Request to create a new task."""
    name: str
    description: str
    category: str = "custom"
    prompt: str
    system_prompt: Optional[str] = None
    tags: List[str] = []


@router.get("", response_model=List[TaskResponse])
async def list_tasks(category: Optional[str] = None):
    """List all tasks from the library."""
    library = get_task_library()
    tasks = library.list_tasks(category)

    return [
        TaskResponse(
            id=t.id,
            name=t.name,
            description=t.description,
            category=t.category,
            prompt=t.prompt[:200] + "..." if len(t.prompt) > 200 else t.prompt,
            tags=t.tags,
            is_preset=t.is_preset,
            estimated_tokens=t.estimated_tokens,
        )
        for t in tasks
    ]


@router.get("/{task_id}")
async def get_task(task_id: str):
    """Get a specific task from the library."""
    library = get_task_library()
    task = library.get_task(task_id)

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return {
        "id": task.id,
        "name": task.name,
        "description": task.description,
        "category": task.category,
        "prompt": task.prompt,
        "system_prompt": task.system_prompt,
        "tools_required": task.tools_required,
        "tags": task.tags,
        "is_preset": task.is_preset,
        "estimated_tokens": task.estimated_tokens,
        "created_at": task.created_at,
        "updated_at": task.updated_at,
    }


@router.post("")
async def create_task(request: CreateTaskRequest):
    """Create a new task in the library."""
    library = get_task_library()

    task = Task(
        id=f"custom_{uuid.uuid4().hex[:8]}",
        name=request.name,
        description=request.description,
        category=request.category,
        prompt=request.prompt,
        system_prompt=request.system_prompt,
        tags=request.tags,
        is_preset=False,
    )

    library.create_task(task)
    return {"message": "Task created", "task_id": task.id}


@router.delete("/{task_id}")
async def delete_task(task_id: str):
    """Delete a task from the library (cannot delete presets)."""
    library = get_task_library()
    task = library.get_task(task_id)

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if task.is_preset:
        raise HTTPException(status_code=400, detail="Cannot delete preset tasks")

    if library.delete_task(task_id):
        return {"message": f"Task {task_id} deleted"}
    else:
        raise HTTPException(status_code=500, detail="Failed to delete task")

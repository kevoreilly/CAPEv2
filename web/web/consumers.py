import json
from django.conf import settings
from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from lib.cuckoo.core.database import Database

class DashboardConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        user = self.scope["user"]
        
        # Security Check
        if settings.WEB_AUTHENTICATION and not user.is_authenticated:
            if not settings.ANON_VIEW:
                await self.close()
                return

        self.room_group_name = 'dashboard'

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    # Receive status update from room group
    async def task_status_update(self, event):
        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'type': 'status_update',
            'task_id': event['task_id'],
            'status': event['status']
        }))

class TaskConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.task_id = self.scope['url_route']['kwargs']['task_id']
        user = self.scope["user"]
        
        # Security Check 1: Authentication
        if settings.WEB_AUTHENTICATION and not user.is_authenticated:
            if not settings.ANON_VIEW:
                await self.close()
                return

        # Security Check 2: Authorization (Ownership)
        # We need to verify if the user is allowed to view this specific task.
        if settings.WEB_AUTHENTICATION and user.is_authenticated and not user.is_staff:
             # Use sync_to_async to query the DB without blocking
            db = Database()
            task = await sync_to_async(db.view_task)(int(self.task_id))
            
            if not task:
                # Task doesn't exist
                await self.close()
                return

            # Check ownership
            # Note: task.user_id comes from SQLAlchemy, user.id from Django
            # If task.user_id is None, it might be a system task or old task, usually accessible to all or none?
            # Assuming if user_id is set, it restricts access.
            if task.user_id and task.user_id != user.id:
                 await self.close()
                 return

        self.room_group_name = f'task_{self.task_id}'

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    # Receive message from room group
    async def task_log(self, event):
        message = event['message']

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'log': message
        }))

    async def task_status(self, event):
        status = event['status']
        await self.send(text_data=json.dumps({
            'status': status
        }))

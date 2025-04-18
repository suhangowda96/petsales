import uuid
from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from storages.backends.s3boto3 import S3Boto3Storage

class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)  # Explicitly set UUID
    full_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    profile_image = models.URLField(blank=True, null=True)
    bio = models.TextField(blank=True, null=True)
    otp = models.CharField(max_length=6, blank=True, null=True)
    pending_email = models.EmailField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # Remove username field
    username = None
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name']

    def get_full_name(self):
        return self.full_name

    def __str__(self):
        return self.email

class Ad(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="ads", to_field="id")
    title = models.CharField(max_length=255, default="Untitled")  # Default title
    description = models.TextField(default="No description available")  # Default description
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)  # Default price
    location = models.CharField(max_length=255, default="Unknown Location")  # Default location
    pincode = models.CharField(max_length=10, default="000000")  # Default pincode
    pet_type = models.CharField(max_length=50, default="Unknown")  # Default pet type
    breed = models.CharField(max_length=255, default="Unknown")  # Default breed
    images = models.JSONField(default=list)
    is_active = models.BooleanField(default=True)  # Added missing field
    created_at = models.DateTimeField(auto_now_add=True)

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected')
    ]
    
    status = models.CharField(
        max_length=10, 
        choices=STATUS_CHOICES, 
        default='pending'
    )
    
    
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title  

class Review(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reviews_received')
    reviewer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reviews_given')
    rating = models.PositiveIntegerField()
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    class Meta:
        unique_together = ['user', 'reviewer']  # Prevent duplicate reviews

    def __str__(self):
        return f"{self.rating}★ review by {self.reviewer.email}"

# Add to models.py
class Conversation(models.Model):
    user1 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='conversations1')
    user2 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='conversations2')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user1', 'user2')

    def __str__(self):
        return f"{self.user1.email} - {self.user2.email}"

# models.py
class Message(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        unique=True
    )
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    ad = models.ForeignKey(Ad, on_delete=models.SET_NULL, null=True, blank=True)  # Changed to SET_NULL
    content = models.TextField(blank=True, default='')
    image_url = models.URLField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    is_deleted = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']

class Favorite(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='favorites')
    ad = models.ForeignKey(Ad, on_delete=models.CASCADE, related_name='favorited_by')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'ad') 


class Report(models.Model):
    REASON_CHOICES = [
        ('spam', 'Spam or misleading'),
        ('fake', 'Fake or scam'),
        ('illegal', 'Illegal activity'),
        ('wrong_category', 'Wrong category'),
        ('sold', 'Already sold'),
        ('other', 'Other')
    ]

    reporter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reports_made')
    ad = models.ForeignKey(Ad, on_delete=models.CASCADE, related_name='reports')
    reason = models.CharField(max_length=20, choices=REASON_CHOICES)
    details = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)

    class Meta:
        unique_together = ('reporter', 'ad')  # Prevent duplicate reports

    def __str__(self):
        return f"Report on {self.ad.title} by {self.reporter.email}"

# models.py
class HelpRequest(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    name = models.CharField(max_length=255)
    email = models.EmailField()
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Help Request from {self.name} ({self.email})"
    

class Notification(models.Model):
    TYPE_CHOICES = [
        ('info', 'Info'),
        ('success', 'Success'),
        ('warning', 'Warning'),
        ('error', 'Error'),
    ]
    
    title = models.CharField(max_length=255)
    message = models.TextField()
    notification_type = models.CharField(max_length=20, choices=TYPE_CHOICES, default='info')
    target_user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True,
        related_name='targeted_notifications'
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    is_broadcast = models.BooleanField(default=True)
    recipients = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='notifications')
    data = models.JSONField(null=True, blank=True)

    def __str__(self):
        return self.title
    
class DeletionReason(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    REASON_CHOICES = [
        ('privacy', 'Privacy concerns'),
        ('usage', "Don't use the service anymore"),
        ('alternate', 'Found a better alternative'),
        ('cost', 'Too expensive'),
        ('confusing', 'Too confusing to use'),
        ('other', 'Other')
    ]
    
    email = models.EmailField()
    full_name = models.CharField(max_length=255)
    reason = models.CharField(max_length=20, choices=REASON_CHOICES)
    description = models.TextField(blank=True, null=True)
    deleted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'deletion_reasons'
        indexes = [
            models.Index(fields=['email']),
        ]

    def __str__(self):
        return f"Deletion by {self.email} - {self.get_reason_display()}"
    
import random
import uuid 
import smtplib
from email.mime.text import MIMEText
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
from django.core.files.storage import default_storage
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.core.exceptions import PermissionDenied
from django.core.exceptions import ValidationError 
from django.core.files.base import ContentFile
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.core.cache import cache
from users.models import Ad  
from .models import Message, User
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser 
from rest_framework.decorators import  api_view, permission_classes, parser_classes
from rest_framework import serializers
from rest_framework import generics
import json
import os
from io import BytesIO
from PIL import Image
from users.models import  Ad, User
from decimal import Decimal, InvalidOperation
from supabase import create_client, Client
from django.conf import settings
import magic
from .models import Review, Favorite, Conversation, Message, Report, Notification, DeletionReason
from dotenv import load_dotenv
from urllib.parse import urlparse, unquote
import traceback
from django.db.models import Q, F, Avg
from django.contrib.postgres.search import TrigramSimilarity
from django.db.models import F, FloatField, ExpressionWrapper, Q, DecimalField
from decimal import Decimal
from storages.backends.s3boto3 import S3Boto3Storage
from .serializers import ReviewSerializer, AdSerializer, HelpRequestSerializer, NotificationSerializer


# Function to send OTP email
def send_otp_email(email, otp):
    sender_email = "petdeals96@gmail.com"  # Replace with your Gmail
    sender_password = "chix zlds jowk wmcc"  # Use App Password if 2FA is enabled

    subject = "Your OTP Code"
    body = f"Your OTP for verification is: {otp}"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = email

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending OTP: {e}")
        return False

@csrf_exempt
def signup(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            is_resend = data.get("resend", False)
            email = data.get("email")

            if is_resend:
                # Handle OTP resend
                if not email:
                    return JsonResponse({"error": "Email is required for resend"}, status=400)

                # Check existing OTP data
                existing_data = cache.get(f"otp_{email}")
                if not existing_data:
                    return JsonResponse({"error": "No active OTP request found"}, status=400)

                # Generate new OTP
                new_otp = str(random.randint(100000, 999999))
                if not send_otp_email(email, new_otp):
                    return JsonResponse({"error": "Failed to send OTP"}, status=500)

                # Update cache with new OTP but keep existing user data
                cache.set(f"otp_{email}", {
                    "otp": new_otp,
                    "full_name": existing_data["full_name"],
                    "password": existing_data["password"]
                }, timeout=300)

                return JsonResponse({"message": "OTP resent successfully"}, status=200)

            # Original signup logic
            full_name = data.get("full_name")
            password = data.get("password")

            if not full_name or not email or not password:
                return JsonResponse({"error": "All fields are required"}, status=400)

            if User.objects.filter(email=email).exists():
                return JsonResponse({"error": "Email already exists"}, status=400)

            otp = str(random.randint(100000, 999999))
            if not send_otp_email(email, otp):
                return JsonResponse({"error": "Failed to send OTP"}, status=500)

            cache.set(f"otp_{email}", {
                "otp": otp,
                "full_name": full_name,
                "password": make_password(password)
            }, timeout=300)

            return JsonResponse({"message": "OTP sent. Please verify."}, status=200)
        
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

    return JsonResponse({"error": "Invalid request method"}, status=405)


@csrf_exempt
def verify_otp(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data.get("email")
            entered_otp = data.get("otp")

            if not email or not entered_otp:
                return JsonResponse({"error": "Email and OTP are required"}, status=400)

            cached_data = cache.get(f"otp_{email}")

            if not cached_data:
                return JsonResponse({"error": "OTP expired. Please request a new one."}, status=400)
            if cached_data["otp"] != entered_otp:
                return JsonResponse({"error": "Invalid OTP"}, status=400)

            # Create user
            user = User.objects.create(
                email=email,
                full_name=cached_data["full_name"],
                password=cached_data["password"]
            )

            Notification.objects.create(
                title="Welcome to PetSales! 🐾",
                message=f"Hi {user.full_name}, thanks for joining our pet-loving community!",
                notification_type='success',
                target_user=user,
                is_broadcast=False  # Mark as non-broadcast
            )

            
            # Generate JWT token
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            
            cache.delete(f"otp_{email}")

            return JsonResponse({
                "message": "Registration successful",
                "access_token": access_token,
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "full_name": user.full_name
                }
            }, status=200)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def login(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data.get("email")
            password = data.get("password")

            if not email or not password:
                return JsonResponse({"error": "Email and password are required"}, status=400)

            user = User.objects.filter(email=email).first()
            if not user or not check_password(password, user.password):
                return JsonResponse({"error": "Invalid email or password"}, status=401)

            refresh = RefreshToken.for_user(user)
            
            return JsonResponse({
                "message": "Login successful",
                "access_token": str(refresh.access_token),
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "full_name": user.get_full_name() or email.split('@')[0]
                }
            }, status=200)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)
    return JsonResponse({"error": "Invalid request method"}, status=405)


def validate_image(file):
    # Validate file type and size
    mime = magic.Magic()
    file_type = mime.from_buffer(file.read(1024))
    file.seek(0)
    
    if "image" not in file_type.lower():
        raise ValueError("Invalid file type")
    if file.size > 10 * 1024 * 1024:  # 10MB
        raise ValueError("File size exceeds 10MB limit")
    return True

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def post_ad(request):
    try:
        data = request.data
         
        # Verify image URLs belong to your Supabase domain
        valid_domain = "supabase.co"  # Change to your domain
        for img_url in data.get("images", []):
            if valid_domain not in img_url:
                return Response({"error": "Invalid image source"}, status=400)

        
        # Validate required fields
        required_fields = ["title", "description", "price", "location", 
                         "pincode", "pet_type", "breed", "images"]
        if not all(data.get(field) for field in required_fields):
            return Response({"error": "Missing required fields"}, status=400)

        # Create ad with image URLs
        ad = Ad.objects.create(
            user=request.user,
            title=data["title"],
            description=data["description"],
            price=Decimal(data["price"]),
            location=data["location"],
            pincode=data["pincode"],
            pet_type=data["pet_type"],
            breed=data["breed"],
            images=data["images"]
        )

        return Response({
            "message": "Ad created successfully",
            "ad_id": ad.id,
            "images": data["images"]
        }, status=201)

    except Exception as e:
        return Response({"error": str(e)}, status=400)


#profile
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def profile_details(request):
    user = request.user
    return Response({
        'id': str(user.id),
        'full_name': user.full_name,
        'email': user.email,  # Add this line
        'profile_image': user.profile_image,
        'bio': user.bio,  # Add this line
        'join_date': user.created_at.strftime("%B %Y")
    }, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_active_ads(request):
    ads = Ad.objects.filter(user=request.user, is_active=True)
    serializer = [{
        'id': str(ad.id),
        'title': ad.title,
        'price': str(ad.price),
        'images': ad.images,
        'created_at': ad.created_at.isoformat(),
        'location': ad.location,
        'pincode': ad.pincode,
        'petType': ad.pet_type,  # Make sure this matches your model field name
        'breed': ad.breed,
        'description': ad.description
    } for ad in ads]
    return Response(serializer)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_ad(request, ad_id):
    try:
        ad = Ad.objects.get(id=ad_id, user=request.user)
        
        # Delete images from Supabase
        supabase = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))
        for image_url in ad.images:
            file_name = image_url.split('/')[-1]
            supabase.storage.from_('pet-images').remove([file_name])
        
        ad.delete()
        return Response(status=204)
    except Ad.DoesNotExist:
        return Response({'error': 'Ad not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_reviews(request):
    reviews = Review.objects.filter(user=request.user)
    serializer = [{
        'id': review.id,
        'rating': review.rating,
        'comment': review.comment,
        'reviewer_name': review.reviewer.full_name,
        'created_at': review.created_at
    } for review in reviews]
    return Response(serializer)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def ad_operations(request, ad_id):
    try:
        ad = Ad.objects.get(id=ad_id, user=request.user)
    except Ad.DoesNotExist:
        return Response({'error': 'Ad not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        return Response({
            'id': str(ad.id),
            'title': ad.title,
            'price': str(ad.price),
            'description': ad.description,
            'images': ad.images,
            'location': ad.location,
            'pincode': ad.pincode,
            'petType': ad.pet_type,
            'breed': ad.breed,
            'created_at': ad.created_at.isoformat()
        }, status=status.HTTP_200_OK)

    elif request.method == 'DELETE':
        try:
            supabase = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))
            for image_url in ad.images:
                file_name = image_url.split('/')[-1]
                supabase.storage.from_('pet-images').remove([file_name])
            ad.delete()
            return Response(status=204)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    elif request.method == 'PUT':
        try:
            data = request.data
            ad.title = data.get('title', ad.title)
            ad.price = Decimal(data.get('price', ad.price))
            ad.description = data.get('description', ad.description)
            ad.images = data.get('images', ad.images)
            ad.location = data.get('location', ad.location)
            ad.pincode = data.get('pincode', ad.pincode)
            ad.pet_type = data.get('petType', ad.pet_type)
            ad.breed = data.get('breed', ad.breed)
            ad.save()
            
            return Response({
                'id': str(ad.id),
                'title': ad.title,
                'price': str(ad.price),
                'description': ad.description,
                'images': ad.images,
                'location': ad.location,
                'pincode': ad.pincode,
                'petType': ad.pet_type,
                'breed': ad.breed,
                'created_at': ad.created_at.isoformat()
            }, status=status.HTTP_200_OK)
        except InvalidOperation:
            return Response({'error': 'Invalid price format'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

# pofile part
@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_profile(request):
    user = request.user
    data = request.data
    
    # Handle profile image deletion
    if 'profile_image' in data and data['profile_image'] is None:
        if user.profile_image:
            try:
                # Extract filename from URL
                file_name = user.profile_image.split('/')[-1]
                supabase.storage.from_('profile-images').remove([file_name])
            except Exception as e:
                print(f"Error deleting image: {str(e)}")
        
        user.profile_image = None
    
    # Handle profile image update
    if 'profile_image' in data and data['profile_image'] is not None:
        # Delete old image if exists
        if user.profile_image:
            try:
                old_file_name = user.profile_image.split('/')[-1]
                supabase.storage.from_('profile-images').remove([old_file_name])
            except Exception as e:
                print(f"Error deleting old image: {str(e)}")
        
        user.profile_image = data['profile_image']
    
    # Update other fields
    user.full_name = data.get('full_name', user.full_name)
    user.bio = data.get('bio', user.bio)
    user.email = data.get('email', user.email)
    
    user.save()
    
    return Response({
        'full_name': user.full_name,
        'profile_image': user.profile_image,
        'bio': user.bio,
        'email': user.email
    })

# views.py
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_email(request):
    """Check if an email exists in the system (excluding current user's email)"""
    email = request.query_params.get('email')
    if not email:
        return Response({'error': 'Email parameter is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    exists = User.objects.filter(email=email).exclude(id=request.user.id).exists()
    return Response({'exists': exists}, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_verification(request):
    """Send OTP for email verification to new email address"""
    email = request.data.get('email')
    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

    # Check if email is already used by another user
    if User.objects.filter(email=email).exclude(id=request.user.id).exists():
        return Response({'error': 'Email already registered with another account'}, 
                      status=status.HTTP_400_BAD_REQUEST)

    # Generate 6-digit OTP
    otp = str(random.randint(100000, 999999))
    
    # Send OTP via email
    if not send_otp_email(email, otp):
        return Response({'error': 'Failed to send verification code'},
                      status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Store OTP in cache with user context
    cache_key = f'email_verification:{email}'
    cache.set(cache_key, {
        'user_id': request.user.id,
        'otp': otp,
        'current_email': request.user.email
    }, timeout=300)  # 5 minutes expiration

    return Response({'message': 'Verification code sent successfully'}, 
                  status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_email(request):
    """Verify OTP and update user email"""
    email = request.data.get('email')
    otp = request.data.get('otp')
    
    if not email or not otp:
        return Response({'error': 'Email and OTP are required'}, 
                      status=status.HTTP_400_BAD_REQUEST)

    cache_key = f'email_verification:{email}'
    cached_data = cache.get(cache_key)

    # Validate OTP
    if not cached_data or cached_data['otp'] != otp:
        return Response({'error': 'Invalid verification code'}, 
                      status=status.HTTP_400_BAD_REQUEST)

    # Ensure the request is coming from the same user who initiated the verification
    if cached_data['user_id'] != request.user.id:
        return Response({'error': 'Verification mismatch'}, 
                      status=status.HTTP_401_UNAUTHORIZED)

    # Update user email
    try:
        user = User.objects.get(id=request.user.id)
        user.email = email
        user.save()
        
        # Cleanup cached OTP
        cache.delete(cache_key)
        
        return Response({'message': 'Email updated successfully'}, 
                      status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': str(e)}, 
                      status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# home
@api_view(['GET'])
def get_all_ads(request):
    ads = Ad.objects.filter(is_active=True).select_related('user')
    serializer = [{
        'id': str(ad.id),
        'title': ad.title,
        'price': str(ad.price),
        'images': ad.images,
        'created_at': ad.created_at.isoformat(),
        'location': ad.location,
        'pincode': ad.pincode,
        'petType': ad.pet_type,
        'breed': ad.breed,
        'description': ad.description,
        'user_full_name': ad.user.full_name,
        'user_id': str(ad.user.id),
        'user_email': ad.user.email,
        'user_profile_image': ad.user.profile_image
    } for ad in ads]
    return Response(serializer)



# Update MessageSerializer
# Initialize Supabase client
supabase = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))

def validate_image(file):
    """Validate image file type and size"""
    mime = magic.Magic()
    file.seek(0)
    file_type = mime.from_buffer(file.read(1024))
    file.seek(0)
    
    if "image" not in file_type.lower():
        raise ValueError("Invalid file type. Only images are allowed.")
    if file.size > 10 * 1024 * 1024:  # 10MB
        raise ValueError("File size exceeds 10MB limit.")
    return True

class MessageSerializer(serializers.ModelSerializer):
    ad_title = serializers.SerializerMethodField()
    
    class Meta:
        model = Message
        fields = ['id', 'sender', 'receiver', 'ad', 'content', 
                 'timestamp', 'is_read', 'ad_title', 'image_url']
        extra_kwargs = {
            'sender': {'read_only': True},
            'receiver': {'required': True},
            'ad': {'required': False},
        }

    def get_ad_title(self, obj):
        return obj.ad.title if obj.ad else None

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_conversations(request):
    conversations = Conversation.objects.filter(
        Q(user1=request.user) | Q(user2=request.user)
    )
    
    # Use correct related name 'messages' instead of 'message_set'
    conversations = conversations.select_related('user1', 'user2').prefetch_related('messages')

    serialized = []
    for conv in conversations:
        other_user = conv.user2 if conv.user1 == request.user else conv.user1
        # Corrected: use 'messages' instead of 'message_set'
        last_message = conv.messages.order_by('-timestamp').first()
        
        # Corrected: use 'messages' here too
        unread_count = conv.messages.filter(
            sender=other_user,
            receiver=request.user,
            is_read=False
        ).count()

        serialized.append({
            'user_id': str(other_user.id),
            'user_name': other_user.full_name,
            'user_avatar': other_user.profile_image or None,
            'last_message': last_message.content if last_message else '',
            'timestamp': last_message.timestamp.isoformat() if last_message else conv.created_at.isoformat(),
            'unread': unread_count > 0
        })
    
    serialized.sort(key=lambda x: x['timestamp'], reverse=True)
    return Response(serialized)


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def conversation_messages(request, user_id):
    other_user = get_object_or_404(User, id=user_id)
    ad_id = request.query_params.get('adId')

    # Get conversation with ad context
    conversation, created = Conversation.objects.get_or_create(
        user1=min(request.user, other_user, key=lambda u: str(u.id)),
        user2=max(request.user, other_user, key=lambda u: str(u.id))
    )

    if request.method == 'GET':
        # Get messages with ad filter if present
        messages = Message.objects.filter(
            Q(sender=request.user, receiver=other_user) |
            Q(receiver=request.user, sender=other_user)
        )
        if ad_id:
            messages = messages.filter(ad_id=ad_id)
            
        messages = messages.order_by('timestamp')
        serializer = MessageSerializer(messages, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        data = request.data.copy()
        image_file = request.FILES.get('image')

        # Handle image upload
        if image_file:
            try:
                validate_image(image_file)
                
                # Generate unique filename
                file_ext = image_file.name.split('.')[-1]
                file_name = f"{uuid.uuid4()}.{file_ext}"
                
                # Upload to Supabase
                file_content = image_file.read()
                res = supabase.storage.from_('messages').upload(
                    file_name, 
                    file_content,
                    {'content-type': image_file.content_type}
                )
                
                # Get public URL and add to data
                public_url = supabase.storage.from_('messages').get_public_url(file_name)
                data['image_url'] = public_url  # Changed to image_url
                
            except Exception as e:
                return Response({'error': f'Image upload failed: {str(e)}'}, 
                              status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        data['receiver'] = str(other_user.id)

        # Validate ad reference
        ad_id = data.get('ad')
        if ad_id:
            try:
                Ad.objects.get(id=ad_id)
            except (Ad.DoesNotExist, ValidationError):
                return Response({'error': 'Invalid ad ID'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = MessageSerializer(data=data)
        if serializer.is_valid():
            serializer.save(
                sender=request.user,
                conversation=conversation,
                receiver=other_user
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def mark_messages_read(request, user_id):
    other_user = get_object_or_404(User, id=user_id)
    
    # Get conversation and mark messages as read
    conversation = Conversation.objects.filter(
        Q(user1=request.user, user2=other_user) |
        Q(user1=other_user, user2=request.user)
    ).first()
    
    if conversation:
        Message.objects.filter(
            conversation=conversation,
            sender=other_user,
            receiver=request.user,
            is_read=False
        ).update(is_read=True)
    
    return Response({'status': 'messages marked as read'}, status=status.HTTP_200_OK)
    


#delete
def extract_supabase_path(image_url: str, bucket_name: str) -> str:
    """Extracts the correct storage path from Supabase URL"""
    try:
        # Decode URL and handle special characters
        parsed_url = urlparse(unquote(image_url))
        path = parsed_url.path
        
        # Find bucket position
        bucket_index = path.find(f"/{bucket_name}/")
        if bucket_index == -1:
            raise ValueError(f"Bucket '{bucket_name}' not found in URL")
        
        # Extract path after bucket and clean it
        file_path = path[bucket_index + len(f"/{bucket_name}/"):]
        
        # Remove leading/trailing slashes and query params
        return file_path.strip('/').split('?')[0]
        
    except Exception as e:
        print(f"Error parsing image URL: {str(e)}")
        raise
        
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_conversation(request, user_id):
    other_user = get_object_or_404(User, id=user_id)
    supabase = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))
    
    try:
        conversation = Conversation.objects.filter(
            Q(user1=request.user, user2=other_user) |
            Q(user1=other_user, user2=request.user)
        ).first()

        if not conversation:
            return Response({'error': 'Conversation not found'}, status=404)

        messages = Message.objects.filter(conversation=conversation)
        # Delete associated images
        for message in messages:
            if message.image_url:
                try:
                    file_path = extract_supabase_path(message.image_url, "messages")
                    res = supabase.storage.from_('messages').remove([file_path])
                    if res.error:
                        print(f"Supabase error: {res.error.code} - {res.error.message}")
                        # Continue despite Supabase errors to ensure DB deletion
                except Exception as e:
                    print(f"Error deleting image: {str(e)}")
                    # Continue to delete DB entries even if image deletion fails

        # Delete messages and conversation
        deleted_messages_count, _ = messages.delete()
        print(f"Deleted {deleted_messages_count} messages.")
        
        conversation.delete()
        print(f"Deleted conversation {conversation.id}.")
        
        return Response({'status': 'conversation deleted'}, status=200)

    except Exception as e:
        print(f"Error traceback: {traceback.format_exc()}")
        return Response({'error': str(e)}, status=500)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_single_message(request, message_id):
    supabase = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))
    
    try:
        message = get_object_or_404(Message, id=message_id)
        
        # Verify ownership
        if request.user not in [message.sender, message.receiver]:
            return Response({'error': 'Unauthorized'}, status=403)

        # Delete image
        deletion_error = None
        if message.image_url:
            try:
                file_path = extract_supabase_path(message.image_url, "messages")
                print(f"Deleting file at path: {file_path}")
                
                # Supabase returns list of results
                results = supabase.storage.from_('messages').remove([file_path])
                
                # Check each result in the list
                for res in results:
                    if res.get('error'):
                        deletion_error = {
                            'message': res['error'].get('message', 'Unknown error'),
                            'code': res['error'].get('code', 'unknown')
                        }
                        print(f"Supabase error: {deletion_error}")
                        break
                
            except Exception as e:
                print(f"Image deletion error: {traceback.format_exc()}")
                deletion_error = str(e)

        if deletion_error:
            return Response({
                'error': 'File deletion failed',
                'details': deletion_error
            }, status=500)

        message.delete()
        return Response(status=204)

    except Exception as e:
        print(f"Error traceback: {traceback.format_exc()}")
        return Response({'error': str(e)}, status=400)
                      
# Bulk Message Deletion
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_selected_messages(request, user_id):
    supabase = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))
    
    try:
        other_user = get_object_or_404(User, id=user_id)
        message_ids = request.data.get('message_ids', [])
        
        if not message_ids:
            return Response({'error': 'No messages selected'}, status=400)

        conversation = get_object_or_404(Conversation,
            Q(user1=request.user, user2=other_user) |
            Q(user1=other_user, user2=request.user)
        )

        messages = Message.objects.filter(
            id__in=message_ids,
            conversation=conversation
        )

        # Delete associated images
        for message in messages:
            if message.image_url:
                try:
                    file_path = extract_supabase_path(message.image_url, "messages")
                    res = supabase.storage.from_('messages').remove([file_path])
                    if res.error:
                        print(f"Supabase error: {res.error.message}")
                except Exception as e:
                    print(f"Error deleting image: {str(e)}")

        messages.delete()
        return Response(status=204)

    except Exception as e:
        return Response({'error': str(e)}, status=400)

# profile part
@api_view(['GET'])
def profile_view(request, user_id):
    try:
        user = User.objects.get(id=user_id)
        return Response({
            'id': str(user.id),
            'full_name': user.full_name,
            'profile_image': user.profile_image,
            'bio': user.bio,
            'join_date': user.created_at.strftime("%B %Y")
        }, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=404)

@api_view(['GET'])
def user_ads_view(request, user_id):
    ads = Ad.objects.filter(user_id=user_id, is_active=True)
    serializer = [{
        'id': str(ad.id),
        'title': ad.title,
        'price': str(ad.price),
        'images': ad.images,
        'created_at': ad.created_at.isoformat(),
        'location': ad.location,
        'pincode': ad.pincode,
        'petType': ad.pet_type,
        'breed': ad.breed,
        'description': ad.description
    } for ad in ads]
    return Response(serializer)

@api_view(['GET'])
def user_reviews_view(request, user_id):
    reviews = Review.objects.filter(user_id=user_id)
    serializer = [{
        'id': review.id,
        'rating': review.rating,
        'comment': review.comment,
        'reviewer_name': review.reviewer.full_name,
        'reviewer_id': str(review.reviewer.id),
        'created_at': review.created_at
    } for review in reviews]
    return Response(serializer)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_review(request, user_id):
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    # Prevent self-reviews
    if request.user.id == user_id:
        return Response({'error': 'You cannot review yourself'}, status=status.HTTP_400_BAD_REQUEST)

    # Check for existing review
    if Review.objects.filter(user=user, reviewer=request.user).exists():
        return Response({'error': 'You have already reviewed this user'}, 
                      status=status.HTTP_400_BAD_REQUEST)

    serializer = ReviewSerializer(data=request.data)
    if serializer.is_valid():
        # Create review with both users
        review = serializer.save(
            user=user,
            reviewer=request.user
        )
        return Response({
            'id': review.id,
            'rating': review.rating,
            'comment': review.comment,
            'reviewer_name': review.reviewer.full_name,
            'created_at': review.created_at
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_review(request, user_id):
    exists = Review.objects.filter(
        user_id=user_id, 
        reviewer=request.user
    ).exists()
    return Response({'hasReviewed': exists})

@api_view(['PUT', 'PATCH'])
@permission_classes([IsAuthenticated])
def update_review(request, review_id):
    try:
        review = Review.objects.get(id=review_id, reviewer=request.user)
    except Review.DoesNotExist:
        return Response(
            {'error': 'Review not found or unauthorized'}, 
            status=status.HTTP_404_NOT_FOUND
        )

    serializer = ReviewSerializer(review, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Favorites API Views
@api_view(['GET', 'POST', 'DELETE'])
@permission_classes([IsAuthenticated])
def favorites_api(request, ad_id=None):
    try:
        if request.method == 'GET' and not ad_id:
            favorites = Favorite.objects.filter(user=request.user).select_related('ad')
            serializer = [{
                'id': str(fav.id),
                'ad': {
                    'id': str(fav.ad.id),
                    'title': fav.ad.title,
                    'price': str(fav.ad.price),
                    'images': fav.ad.images,
                    'location': fav.ad.location,
                    'pincode': fav.ad.pincode,
                    'petType': fav.ad.pet_type,
                    'breed': fav.ad.breed,
                    'description': fav.ad.description,
                    'created_at': fav.ad.created_at.isoformat(),
                    'user_full_name': fav.ad.user.full_name,
                    'user_id': str(fav.ad.user.id),
                    'user_profile_image': fav.ad.user.profile_image.url if fav.ad.user.profile_image else None,
                },
                'created_at': fav.created_at.isoformat()
            } for fav in favorites]
            return Response(serializer, status=status.HTTP_200_OK)

        # Handle single ad operations
        try:
            ad = Ad.objects.get(id=ad_id)
        except Ad.DoesNotExist:
            return Response({'error': 'Ad not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check existing favorite
        favorite = Favorite.objects.filter(user=request.user, ad=ad).first()

        # Handle POST (create favorite)
        if request.method == 'POST':
            if favorite:
                return Response({'error': 'Already favorited'}, status=status.HTTP_400_BAD_REQUEST)
                
            favorite = Favorite.objects.create(user=request.user, ad=ad)
            return Response({
                'id': str(favorite.id),
                'ad_id': str(ad.id)
            }, status=status.HTTP_201_CREATED)

        # Handle DELETE (remove favorite)
        if request.method == 'DELETE':
            if not favorite:
                return Response({'error': 'Favorite not found'}, status=status.HTTP_404_NOT_FOUND)
                
            favorite.delete()
            return Response({'status': 'removed from favorites'}, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def search_ads(request):
    try:
        query = request.GET.get('q', '').strip()
        sort_by = request.GET.get('sort', 'newest')
        location = request.GET.get('location', '')
        pet_type = request.GET.get('pet_type', 'all')
        min_price = request.GET.get('min_price', 0)
        max_price = request.GET.get('max_price', 100000)
        min_similarity = 0.2  # Adjust threshold as needed (0-1)

        # Base query
        ads = Ad.objects.filter(is_active=True)
        
        # Search query - using both exact and fuzzy search
        if query:
            # Exact matches
            exact_matches = Q(
                Q(title__icontains=query) |
                Q(description__icontains=query) |
                Q(breed__icontains=query) |
                Q(pet_type__icontains=query) |
                Q(location__icontains=query) |
                Q(user__full_name__icontains=query)
            )
            
            # Fuzzy matches using trigram similarity
            fuzzy_matches = Q(
                Q(title_sim__gte=min_similarity) |
                Q(desc_sim__gte=min_similarity) |
                Q(breed_sim__gte=min_similarity) |
                Q(type_sim__gte=min_similarity) |
                Q(loc_sim__gte=min_similarity) |
                Q(user_sim__gte=min_similarity)
            )
            
            # Annotate with similarity scores and combine both exact and fuzzy matches
            ads = ads.annotate(
                title_sim=TrigramSimilarity('title', query),
                desc_sim=TrigramSimilarity('description', query),
                breed_sim=TrigramSimilarity('breed', query),
                type_sim=TrigramSimilarity('pet_type', query),
                loc_sim=TrigramSimilarity('location', query),
                user_sim=TrigramSimilarity('user__full_name', query),
                total_sim=ExpressionWrapper(
                    F('title_sim') + F('desc_sim') + F('breed_sim') +
                    F('type_sim') + F('loc_sim') + F('user_sim'),
                    output_field=FloatField()
                )
            ).filter(exact_matches | fuzzy_matches)
        
        # Filters
        if location:
            ads = ads.filter(location__icontains=location)
            
        if pet_type.lower() != 'all':
            ads = ads.filter(pet_type__iexact=pet_type)
            
        if min_price and max_price:
            ads = ads.filter(
                price__gte=Decimal(min_price), 
                price__lte=Decimal(max_price)
            )
        
        # Sorting
        if sort_by == 'price_asc':
            ads = ads.order_by('price')
        elif sort_by == 'price_desc':
            ads = ads.order_by('-price')
        elif query:
            # When there's a search query, sort by similarity first, then by date
            ads = ads.order_by('-total_sim', '-created_at')
        else:
            # Default sorting (newest first)
            ads = ads.order_by('-created_at')

        serializer = AdSerializer(ads.distinct(), many=True)
        return Response(serializer.data)
        
    except Exception as e:
        return Response({'error': str(e)}, status=400)

# Report
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def report_ad(request):
    try:
        data = request.data
        ad_id = data.get('ad_id')
        reason = data.get('reason')
        details = data.get('details', '')

        if not ad_id or not reason:
            return Response({'error': 'Ad ID and reason are required'}, 
                          status=status.HTTP_400_BAD_REQUEST)

        try:
            ad = Ad.objects.get(id=ad_id)
        except Ad.DoesNotExist:
            return Response({'error': 'Ad not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check if user already reported this ad
        if Report.objects.filter(reporter=request.user, ad=ad).exists():
            return Response({'error': 'You have already reported this ad'},
                          status=status.HTTP_400_BAD_REQUEST)

        Report.objects.create(
            reporter=request.user,
            ad=ad,
            reason=reason,
            details=details
        )

        return Response({'message': 'Report submitted successfully'}, 
                      status=status.HTTP_201_CREATED)

    except Exception as e:
        return Response({'error': str(e)}, 
                      status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def current_user(request):
    user = request.user
    return Response({
        'id': str(user.id),
        'email': user.email,
        'full_name': user.get_full_name(),
        'profile_image': user.profile_image
    })

#forgot password
@csrf_exempt
def forgot_password(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data.get("email")
            is_resend = data.get("resend", False)

            if not email:
                return JsonResponse({"error": "Email is required"}, status=400)

            user = User.objects.filter(email=email).first()
            if not user:
                return JsonResponse({"error": "User with this email does not exist"}, status=404)

            # Generate and send OTP
            otp = str(random.randint(100000, 999999))
            if not send_otp_email(email, otp):
                return JsonResponse({"error": "Failed to send OTP"}, status=500)

            # Store OTP in cache with user email
            cache.set(f"reset_otp_{email}", otp, timeout=300)
            return JsonResponse({"message": "OTP sent to email"}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)
    return JsonResponse({"error": "Invalid method"}, status=405)

@csrf_exempt
def verify_reset_otp(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data.get("email")
            otp = data.get("otp")

            cached_otp = cache.get(f"reset_otp_{email}")

            if not cached_otp or cached_otp != otp:
                return JsonResponse({"error": "Invalid OTP"}, status=400)

            # Generate reset token
            reset_token = str(uuid.uuid4())
            cache.set(f"reset_token_{email}", reset_token, timeout=900)  # 15 minutes
            return JsonResponse({"message": "OTP verified", "token": reset_token}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)
    return JsonResponse({"error": "Invalid method"}, status=405)

@csrf_exempt
def reset_password(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data.get("email")
            otp = data.get("otp")
            new_password = data.get("new_password")

            # Verify OTP again
            cached_otp = cache.get(f"reset_otp_{email}")
            if not cached_otp or cached_otp != otp:
                return JsonResponse({"error": "Invalid OTP"}, status=400)

            user = User.objects.get(email=email)
            user.password = make_password(new_password)
            user.save()

            # Clear cache
            cache.delete(f"reset_otp_{email}")
            cache.delete(f"reset_token_{email}")

            return JsonResponse({"message": "Password reset successful"}, status=200)

        except User.DoesNotExist:
            return JsonResponse({"error": "User not found"}, status=404)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)
    return JsonResponse({"error": "Invalid method"}, status=405)


# Help request view
@api_view(['POST'])
@parser_classes([JSONParser])
def create_help_request(request):
    try:
        data = request.data.copy()
        user = request.user if request.user.is_authenticated else None
        
        # Auto-fill for authenticated users
        if user:
            data['user'] = user.id
            
        serializer = HelpRequestSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)
        
    except Exception as e:
        return Response({'error': str(e)}, status=500)
    
User = get_user_model()
# views.py (update notification views)
class NotificationListCreateView(generics.ListCreateAPIView):
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Get notifications for logged-in user (targeted + broadcasts)"""
        return Notification.objects.filter(
            Q(target_user=self.request.user) |
            Q(is_broadcast=True)
        ).order_by('-timestamp')

    def perform_create(self, serializer):
        """Users can only create personal notifications"""
        serializer.save(target_user=self.request.user, is_broadcast=False)

class NotificationDetailView(generics.RetrieveDestroyAPIView):
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(target_user=self.request.user)

class ClearNotificationsView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Clear user's notifications"""
        Notification.objects.filter(target_user=request.user).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    try:
        user = request.user
        data = request.data
        
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')

        if not user.check_password(current_password):
            return Response({'error': 'Current password is incorrect'}, 
                          status=status.HTTP_400_BAD_REQUEST)

        if new_password != confirm_password:
            return Response({'error': 'New passwords do not match'},
                          status=status.HTTP_400_BAD_REQUEST)

        # Validate password complexity (customize as needed)
        if len(new_password) < 8:
            return Response({'error': 'Password must be at least 8 characters'},
                          status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()

        # Invalidate existing tokens (optional)
        # tokens = OutstandingToken.objects.filter(user=user)
        # tokens.delete()

        return Response({'message': 'Password updated successfully'}, 
                      status=status.HTTP_200_OK)

    except Exception as e:
        return Response({'error': str(e)}, 
                      status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_account(request):
    user = request.user
    data = request.data
    
    try:
        # Verify password first
        if not check_password(data.get('password'), user.password):
            return Response({'error': 'Invalid password'}, status=status.HTTP_401_UNAUTHORIZED)

        # Store deletion reason without foreign key
        DeletionReason.objects.create(
            email=user.email,
            full_name=user.full_name,
            reason=data.get('reason', 'other'),
            description=data.get('description', '')
        )

        # Delete all user-related data
        supabase = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))
        
        def delete_supabase_file(url):
            """Generic method to delete files from any Supabase bucket"""
            try:
                if not url:
                    return

                # Parse URL and extract bucket/file information
                parsed_url = urlparse(unquote(url))
                path = parsed_url.path
                
                # Split path to get bucket and file path
                parts = path.split('/storage/v1/object/public/')
                if len(parts) < 2:
                    print(f"Invalid Supabase URL format: {url}")
                    return

                bucket_file = parts[1]
                bucket_parts = bucket_file.split('/', 1)
                if len(bucket_parts) != 2:
                    print(f"Invalid bucket/file format: {bucket_file}")
                    return

                bucket_name, file_path = bucket_parts
                
                # Verify we're only deleting from allowed buckets
                allowed_buckets = ['profile-images', 'pet-images', 'messages']
                if bucket_name not in allowed_buckets:
                    print(f"Skipping deletion from unauthorized bucket: {bucket_name}")
                    return

                # Delete the file
                res = supabase.storage.from_(bucket_name).remove([file_path])
                
                if res.error:
                    print(f"Supabase deletion error ({bucket_name}/{file_path}): {res.error.message}")
                else:
                    print(f"Successfully deleted {bucket_name}/{file_path}")
                    
            except Exception as e:
                print(f"Error deleting file {url}: {str(e)}")

        # Delete profile image
        delete_supabase_file(user.profile_image)

        # Delete ads and their images
        for ad in Ad.objects.filter(user=user):
            for image_url in ad.images:
                delete_supabase_file(image_url)
            ad.delete()

        # Delete message images
        for message in Message.objects.filter(Q(sender=user) | Q(receiver=user)):
            delete_supabase_file(message.image_url)
            message.delete()

        # Delete related objects
        Favorite.objects.filter(user=user).delete()
        Review.objects.filter(Q(user=user) | Q(reviewer=user)).delete()
        Report.objects.filter(reporter=user).delete()
        Notification.objects.filter(target_user=user).delete()
        
        # Finally delete the user
        user.delete()

        return Response({'message': 'Account permanently deleted'}, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

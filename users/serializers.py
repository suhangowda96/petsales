from rest_framework import serializers
from .models import User, Ad, Review, HelpRequest, Notification



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['full_name', 'email', 'password']

class AdSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())  # ✅ Handles UUIDs

    class Meta:
        model = Ad
        fields = '__all__'

# serializers.py
class ReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Review
        fields = ['rating', 'comment']
        extra_kwargs = {
            'rating': {'min_value': 1, 'max_value': 5},
            'comment': {'max_length': 500}
        }

class AdSerializer(serializers.ModelSerializer):
    user_full_name = serializers.CharField(source='user.full_name', read_only=True)
    user_profile_image = serializers.CharField(source='user.profile_image', read_only=True)
    user_id = serializers.CharField(source='user.id', read_only=True)

    class Meta:
        model = Ad
        fields = [
            'id', 'title', 'price', 'images', 'created_at', 
            'location', 'pincode', 'pet_type', 'breed', 
            'description', 'user_full_name', 'user_id',
            'user_profile_image'
        ]

# serializers.py
class HelpRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = HelpRequest
        fields = ['name', 'email', 'message']
        extra_kwargs = {
            'name': {'required': True},
            'email': {'required': True},
            'message': {'required': True}
        }

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'title', 'message', 'notification_type', 'timestamp']

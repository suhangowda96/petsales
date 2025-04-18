# users/urls.py
from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('signup/', views.signup, name='signup'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('login/', views.login, name='login'),
    path('users/me/', views.current_user, name='current_user'),
    
    # Profile Management
    path('profile/', views.profile_details, name='profile'),
    path('update-profile/', views.update_profile, name='update_profile'),
    path('check-email/', views.check_email, name='check_email'),
    path('send-verification/', views.send_verification, name='send_verification'),
    path('verify-email/', views.verify_email, name='verify_email'),
    
    # Ads
    path('post_ad/', views.post_ad, name='post_ad'),
    path('ads/active/', views.user_active_ads, name='active_ads'),
    path('ads/<uuid:ad_id>/', views.ad_operations, name='ad_operations'),
    
    # Reviews
    path('reviews/', views.user_reviews, name='reviews'),

    # home
    path('ads/', views.get_all_ads, name='get_all_ads'),

    # messages
    path('conversations/', views.get_conversations, name='get_conversations'),
    path('conversations/<uuid:user_id>/messages/', views.conversation_messages, name='conversation_messages'),
    path('conversations/<uuid:user_id>/mark-read/', views.mark_messages_read, name='mark_messages_read'),

    #delte
    path('conversations/<str:user_id>/delete/', views.delete_conversation, name='delete_conversation'),
    path('conversations/<uuid:user_id>/delete-messages/', views.delete_selected_messages, name='delete_selected_messages'),
    path('messages/<uuid:message_id>/', views.delete_single_message, name='delete_single_message'),

    # Public profile endpoints
    path('profile/<uuid:user_id>/', views.profile_view, name='profile-view'),
    path('user-ads/<uuid:user_id>/', views.user_ads_view, name='user-ads'),
    path('user-reviews/<uuid:user_id>/', views.user_reviews_view, name='user-reviews'),
    
    # Review endpoints
    path('reviews/<uuid:user_id>/', views.create_review, name='create-review'),
    path('check-review/<uuid:user_id>/', views.check_review, name='check-review'),
    path('reviews/<int:review_id>/', views.update_review, name='update-review'),

    # favorited
    path('favorites/', views.favorites_api, name='favorites-list'),
    path('favorites/<uuid:ad_id>/', views.favorites_api, name='favorites-detail'),

    # Search
    path('ads/search/', views.search_ads, name='search_ads'),

    #Report
    path('report-ad/', views.report_ad, name='report_ad'),

    #forgot password
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('verify-reset-otp/', views.verify_reset_otp, name='verify_reset_otp'),
    path('reset-password/', views.reset_password, name='reset_password'),

    #help request
    path('help-requests/', views.create_help_request, name='create_help_request'),

    #notification
    path('notifications/', views.NotificationListCreateView.as_view(), name='notifications'),
    path('notifications/clear/', views.ClearNotificationsView.as_view(), name='clear-notifications'),
    path('notifications/<int:pk>/', views.NotificationDetailView.as_view(), name='notification-detail'),

    #settengs
    path('change-password/', views.change_password, name='change_password'),
    path('delete-account/', views.delete_account, name='delete_account'),

]
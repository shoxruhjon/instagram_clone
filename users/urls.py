from django.urls import path
from users.views import (CreateUserView, 
                         VerifyEmailView, 
                         GetNewVerification, 
                         ChangeUserInformationView, 
                         ChangeUserPhotoView, 
                         LoginView, 
                         LoginRefreshView, 
                         ForgotPasswordView,
                         ResetPasswordView)


urlpatterns = [
    path('login/', LoginView.as_view()),
    path('login/refresh/', LoginRefreshView.as_view()),
    path('signup/', CreateUserView.as_view()),
    path('verify/', VerifyEmailView.as_view()),
    path('new-verify/', GetNewVerification.as_view()),
    path('change-user/', ChangeUserInformationView.as_view()),
    path('change-user-photo/', ChangeUserPhotoView.as_view()),
    path('forgot-password/', ForgotPasswordView.as_view()),
    path('reset-password/', ResetPasswordView.as_view()),
]
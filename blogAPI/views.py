from rest_framework import generics, permissions,status
from .models import BlogPost, Comment
from .serializers import BlogPostSerializer, CommentSerializer
from django.shortcuts import render
from django.contrib.auth import login
from django.contrib.auth.models import User
from .serializers import (RegisterSerializer, LoginSerializer)
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.permissions import (AllowAny, IsAuthenticated)
from rest_framework_simplejwt.tokens import (RefreshToken, OutstandingToken, BlacklistedToken)
from rest_framework.authentication import TokenAuthentication


class BlogPostList(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = (TokenAuthentication,)
    queryset = BlogPost.objects.all()
    serializer_class = BlogPostSerializer
    

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)

class BlogPostDetail(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = (TokenAuthentication,)
    queryset = BlogPost.objects.all()
    serializer_class = BlogPostSerializer

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.author==self.request.user:

            self.perform_destroy(instance)
            print(instance)
        else:
            if self.request.user.is_superuser==True:
                self.perform_destroy(instance)
                return Response({'message': 'Blog deleted succesfully by admin .'})
            else:
                return Response({'message': 'You cannot delete Blog created by another User'})    
        return Response({'message': 'Blog deleted succesfully.'})
    

class CommentList(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = (TokenAuthentication,)
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    
    def perform_create(self, serializer):
        serializer.save(author=self.request.user)

class CommentDetail(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = (TokenAuthentication,)
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.author==self.request.user:

            self.perform_destroy(instance)
            print(instance)
        else:
            if self.request.user.is_superuser==True:
                self.perform_destroy(instance)
                return Response({'message': 'Comments deleted succesfully by admin .'})
            else:
                return Response({'message': 'You cannot delete Comments created by another User'})    
        return Response({'message': 'Comments deleted succesfully.'})
    
    



# user system --------------------------------


class RegisterView(generics.CreateAPIView):
    permission_classes = [AllowAny]

    queryset = User.objects.all()
    serializer_class = RegisterSerializer

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(request, user)
        token, created = Token.objects.get_or_create(user=user)
        return Response({"status": status.HTTP_200_OK, "Token": token.key})

class ProfileView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, format=None):
        user = self.request.user
        context = {
            'User' : str(self.request.user), 
            'Email' :str(self.request.user.email),
            'Username' : str(self.request.user.username)
        }
        return Response(context)

class LogoutView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)

class LogoutAllView(generics.GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        tokens = OutstandingToken.objects.filter(user_id=request.user.id)
        for token in tokens:
            t, _ = BlacklistedToken.objects.get_or_create(token=token)

        return Response(status=status.HTTP_205_RESET_CONTENT)

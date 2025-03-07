from django.contrib import admin
from .models import Post, PostLike, PostComment, CommentLike


class PostAdmin(admin.ModelAdmin):
    list_display = ('id', 'author', 'caption')
    search_fields = ('id', 'author__username', 'caption')


class PostCommentAdmin(admin.ModelAdmin):
    list_display = ('id', 'author', 'post')
    search_fields = ('id', 'author__username', 'comment')


class PostLikeAdmin(admin.ModelAdmin):
    list_display = ('id', 'author', 'post')
    search_fields = ('id', 'author__username')


class CommentLikeAdmin(admin.ModelAdmin):
    list_display = ('id', 'author', 'comment')
    search_fields = ('id', 'author__username')


admin.site.register(Post, PostAdmin)
admin.site.register(PostComment, PostCommentAdmin)
admin.site.register(PostLike, PostLikeAdmin)
admin.site.register(CommentLike, CommentLikeAdmin)

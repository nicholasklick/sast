
from django.http import HttpResponse
from .models import Comment

def save_comment(request):
    comment_text = request.POST.get('comment')
    # Assuming Comment model does not escape content
    # Vulnerable to Stored XSS
    comment = Comment(text=comment_text)
    comment.save()
    return HttpResponse("Comment saved.")

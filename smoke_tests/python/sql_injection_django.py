
from django.db import connection
from django.http import HttpResponse

def search_products(request):
    query = request.GET.get('q', '')
    # Vulnerable to SQL Injection
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM products WHERE name = '%s'" % query)
        results = cursor.fetchall()
    return HttpResponse(str(results))

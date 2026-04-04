def process_user_input(request):
    import os
    user_input = request.GET.get('cmd')
    # Vulnerable to command injection
    os.system(user_input)

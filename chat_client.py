import flet as ft
import requests
import threading
import time

server_url = "http://127.0.0.1:5000"

def main(page: ft.Page):
    page.title = "Secure Chat"
    page.window_width = 400
    page.window_height = 600

    username_field = ft.TextField(label="Username")
    password_field = ft.TextField(label="Password", password=True)
    chat_box = ft.Column(scroll="auto")
    message_field = ft.TextField(label="Message", disabled=True)

    access_token = None
    refresh_token = None
    selected_user = None
    selected_username = None
    user_list_view = ft.ListView(spacing=10, expand=1)

 
    def register_user(e):
        username = username_field.value
        password = password_field.value

        if not username or not password:
            page.add(ft.Text("Please provide both username and password!", color="red"))
            page.update()
            return

        response = requests.post(f"{server_url}/register", json={"username": username, "password": password})
        if response.status_code == 201:
            page.add(ft.Text("Registration successful! Please login now.", color="green"))
        elif response.status_code == 409:
            page.add(ft.Text("Username already exists. Please choose a different username.", color="red"))
        else:
            page.add(ft.Text("Registration failed. Please try again.", color="red"))
        page.update()

    def login_user(e):
        nonlocal access_token, refresh_token
        username = username_field.value
        password = password_field.value

        if not username or not password:
            page.add(ft.Text("Please provide both username and password!", color="red"))
            page.update()
            return

        response = requests.post(f"{server_url}/login", json={"username": username, "password": password})
        if response.status_code == 200:
            data = response.json()
            access_token = data['access_token']
            refresh_token = data['refresh_token']
            page.add(ft.Text("Login successful!", color="green"))
            open_user_list_window()
        else:
            page.add(ft.Text("Invalid username or password.", color="red"))
        page.update()


    def open_user_list_window():
        page.clean()
        load_users()  
        page.add(
            ft.Text("Select a user to chat"),
            user_list_view,
        )
        page.update()

   
    def load_users():
        if not access_token:
            page.add(ft.Text("Please login first!", color="red"))
            page.update()
            return

        headers = {"Authorization": access_token}
        response = requests.get(f"{server_url}/users", headers=headers)

        if response.status_code == 200:
            users = response.json()['users']
            user_list_view.controls.clear()
            for user in users:
                if user['username'] != username_field.value:
                    user_id = user['id']
                    username = user['username']
                    user_item = ft.ListTile(
                        title=ft.Text(username),
                        on_click=lambda e, user_id=user_id, username=username: open_chat_window(user_id, username)
                    )
                    user_list_view.controls.append(user_item)
            page.update()

  
    def open_chat_window(user_id, username):
        nonlocal selected_user, selected_username
        selected_user = user_id
        selected_username = username

     
        page.clean()
        load_messages()  
        page.add(
            ft.Text(f"Chat with {selected_username}"), 
            chat_box,
            message_field,
            ft.Row([
                ft.ElevatedButton("Send Message", on_click=send_message),
                ft.ElevatedButton("Back to User List", on_click=back_to_user_list), 
            ]),
        )
        message_field.disabled = False  
        page.update()

      
        def poll_messages():
            while True:
                load_messages()
                time.sleep(5)  

        threading.Thread(target=poll_messages, daemon=True).start()

   
    def load_messages():
        if not access_token or not selected_user:
            page.add(ft.Text("Please login and select a user first!", color="red"))
            page.update()
            return

        headers = {"Authorization": access_token}
        response = requests.get(f"{server_url}/messages/{selected_user}", headers=headers)

        if response.status_code == 200:
            chat_box.controls.clear()
            messages = response.json()['messages']
            for msg in messages:
                if msg['user_id'] == selected_user:
                    
                    chat_box.controls.append(ft.Text(f"{selected_username}: {msg['message']}"))
                else:
                 
                    chat_box.controls.append(ft.Text(f"You: {msg['message']}"))
            page.update()
        else:
            page.add(ft.Text("Failed to load messages.", color="red"))
            page.update()


    def send_message(e):
        if not access_token or not selected_user:
            page.add(ft.Text("Please login and select a user first!", color="red"))
            page.update()
            return

        message = message_field.value
        if not message:
            page.add(ft.Text("Please enter a message.", color="red"))
            page.update()
            return

        headers = {"Authorization": access_token}
        response = requests.post(
            f"{server_url}/send_private",
            headers=headers,
            json={"recipient": selected_user, "message": message}
        )

        if response.status_code == 200:
            chat_box.controls.append(ft.Text(f"You: {message}"))
            message_field.value = ""
            page.update()
        else:
            page.add(ft.Text("Failed to send message.", color="red"))
            page.update()
            print(f"Error: {response.status_code}, {response.text}")  

    
    def back_to_user_list(e):
        open_user_list_window()

  
    page.add(
        username_field,
        password_field,
        ft.ElevatedButton("Register", on_click=register_user),
        ft.ElevatedButton("Login", on_click=login_user),
    )

ft.app(target=main)

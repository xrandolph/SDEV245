#Defining the Users Database
Users = {
    "Xavier" : {"password" : "SDEV245" , "role":"user"},
    "Andrew" : {"password" : "Teacher", "role" : "admin"},
}
#Defining the resources and user permissions
Functions = {
    "Transcript" : {"admin"},
    "Grades" : {"user"},
 }
#Authentification
def authentification (username,password):
    user_data = Users.get(username)
    if user_data and user_data["password"] == password:
        return user_data["role"]
    return None

#Access Control
def has_access(user_role, function):
    allowed_roles = Functions.get(function)
    if allowed_roles and user_role in allowed_roles:
        return True
    return False

#Main App
def main():
    print("Module 1 Access & Authentification")

    username= input("Enter username: ")
    password= input("Enter password: ")
    user_role = authentification(username, password)

    if user_role:
        print(f"\nAuthentification successful! Hello, {username} (Role:{user_role})")
        print(f"\nAvailable Resources:")
        for function, roles in Functions.items():
            access_status = "Granted" if has_access(user_role, function) else "Denied"
            print(f" - {function}: {access_status}")
    else:
        print("\nAuthentification failed. Invalid username or password")
if __name__ == "__main__":

    main()
#This app shows the confidentiality portion of CIA by limiting who can gain access to the system. If the incorrect credentials are entered, the individual can not gain access.

# FINAL

# DockerHub
https://hub.docker.com/repository/docker/dhb9/final/general

# Reflection Document:

Throughout this course, I have gained a lot of insights into the intricacies of software development. I was introduced into a lot of programming concepts that I had previously never realized the importance of. This final project provided a comprehensive learning experience, combining theoretical knowledge with practical application. I struggled a lot on this final project and I really don't think I fully grasped everything that was involved. As I talked to professor Williams throughout the semester he helped me realize that just getting a base understanding of everything involved would really help visualize how everything works together.

One of the most valuable lessons I learned was the critical role of  testing in ensuring the reliability and ability of software. I added 10 new tests, to help identify and rectify potential issues early in the development process. Each test was designed to cover a specific aspect of the user functionality:

# 10 TESTS
    1. Test for Create User Access Denied: Ensures that a regular user cannot create a new user.
    2. Test for Retrieve User Access Denied: Ensures that a regular user cannot access another user's information.
    3. Test for Retrieve User Access Allowed: Verifies that an admin user can access any user's information.
    4. Test for Update User Email Access Denied: Ensures that a regular user cannot update another user's email.
    5. Test for Update User Email Access Allowed: Verifies that an admin user can update any user's email.
    6. Test for Delete User: Confirms that an admin user can delete a user account.
    7. Test for Create User with Duplicate Email: Ensures that the system prevents the creation of users with duplicate emails.
    8. Test for Create User with Invalid Email: Ensures that the system validates email formats during user creation.
    9. Test for Successful Login: Verifies that a user can log in with correct credentials.
    10. Test for Incorrect Login: Ensures that the system rejects login attempts with incorrect credentials.

# FEATURE: User Profile Management
Adding the user management feature was quite a challenge for me. It involved creating, updating, and deleting user accounts, as well as adding extra profile fields to link other socials. I had to learn how to make sure only the right people could access and change this information. I struggled with understanding all the security details and making sure everything worked correctly. I think I got the proper code for it, but it is hard since my CI/CO was constantly failing. I think that was my most difficult aspect. With a lot of research and help from GPT, I was able to get what I think is working code. However, failing to have it properly run through the correct checks makes it completely inoperable.
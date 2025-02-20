document.addEventListener("DOMContentLoaded", function () {
    document.querySelector("form").addEventListener("submit", function (event) {
        const password = document.getElementById("password").value;
        const confirmPassword = document.getElementById("confirm-password").value;
        const errorContainer = document.getElementById("error-message");

        // Password validation: Minimum 8 characters, 1 special character, 1 capital letter, 1 number
        const passwordRegex = /^(?=.*[A-Z])(?=.*[0-9])(?=.*[\W_]).{8,}$/;
        let errorMessages = [];

        // Clear previous messages
        errorContainer.innerHTML = "";
        errorContainer.style.display = "none";

        if (!passwordRegex.test(password)) {
            errorMessages.push("Password must be 8 characters long and have one special character and one uppercase character");
        }

        if (password !== confirmPassword) {
            errorMessages.push("❌ Passwords do not match.");
        }

        if (errorMessages.length > 0) {
            event.preventDefault(); // Prevent form submission
            errorContainer.innerHTML = errorMessages.join("<br><br>");
            errorContainer.style.color = "red";
            errorContainer.style.fontSize = "14px";
            errorContainer.style.display = "block";
        }
    });
});



  // Wait for the document to be ready
  document.addEventListener("DOMContentLoaded", function () {
    // Select all flash messages
    const flashMessages = document.querySelectorAll('.flash-messages .alert');
    
    // Loop through each message
    flashMessages.forEach(function(message) {
      // Set a timer to remove the message after 2 seconds (2000 milliseconds)
      setTimeout(function() {
        message.style.transition = "opacity 0.5s ease-out"; // Add transition effect
        message.style.opacity = "0"; // Fade out the message
        setTimeout(function() {
          message.remove(); // Remove message from the DOM after fading out
        }, 500); // Wait for the fade-out transition to finish (500ms)
      }, 2000); // Delay before starting fade-out (2000ms = 2 seconds)
    });
  });

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
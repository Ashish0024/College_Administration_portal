<?php
// Include config file
require_once "config.php";
 
// Define variables and initialize with empty values
$username = $password = $confirm_password = "";
$username_err = $password_err = $confirm_password_err = $Mobile_Number_err=$Valid_Email_err="";
$Mobile_Number="" ;
$Valid_Email="";
$DATE_OF_BIRTH="";
// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){
 
    // Validate username
    if(empty(trim($_POST["username"]))){
        $username_err = "Please enter a username.";
    } elseif(!preg_match('/^[a-zA-Z0-9_]+$/', trim($_POST["username"]))){
        $username_err = "Username can only contain letters, numbers, and underscores.";
    } else{
        // Prepare a select statement
        $sql = "SELECT id FROM users WHERE username = ?";
        
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "s", $param_username,);
            
            // Set parameters
            $param_username = trim($_POST["username"]);
            
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                /* store result */
                mysqli_stmt_store_result($stmt);
                
                if(mysqli_stmt_num_rows($stmt) == 1){
                    $username_err = "This username is already taken.";
                } else{
                    $username = trim($_POST["username"]);
                }
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }

            // Close statement
            mysqli_stmt_close($stmt);
        }
    }
    
    // Validate password
    if(empty(trim($_POST["password"]))){
        $password_err = "Please enter a password.";     
    } elseif(strlen(trim($_POST["password"])) < 6){
        $password_err = "Password must have atleast 6 characters.";
    } else{
        $password = trim($_POST["password"]);
    }
    $Mobile_Number = trim($_POST["Mobile_Number"]);
    $Valid_Email = trim($_POST["Valid_Email"]);
    $DATE_OF_BIRTH = trim($_POST["DATE_OF_BIRTH"]);
    
    
    // Validate confirm password
    if(empty(trim($_POST["confirm_password"]))){
        $confirm_password_err = "Please confirm password.";     
    } else{
        $confirm_password = trim($_POST["confirm_password"]);
        if(empty($password_err) && ($password != $confirm_password)){
            $confirm_password_err = "Password did not match.";
        }
    }
    
    // Check input errors before inserting in database
    if(empty($username_err) && empty($password_err) && empty($confirm_password_err)){
        
        // Prepare an insert statement
        $sql = "INSERT INTO users (username, password,phoneno,email,DATE_OF_BIRTH) VALUES (?, ?, ?, ?, ?)";
         
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "sssss", $param_username, $param_password,$param_Mobile_Number,$param_Valid_Email,$param_DTAE_OF_BIRTH);
            
            // Set parameters
            $param_username = $username;
            $param_Valid_Email =$Valid_Email;
            $param_Mobile_Number =$Mobile_Number;
            $param_DTAE_OF_BIRTH=$DATE_OF_BIRTH;
            print_r($param_Mobile_Number);
            //die();
             $param_password = password_hashed( $password, PASSWORD_DEFAULT); // Creates a password hash
           // $param_password = $password;
            
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                // Redirect to login page
                header("location: register.php");
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }

            // Close statement
            mysqli_stmt_close($stmt);
        }
    }
    
    // Close connection
    mysqli_close($link);
}
?>
 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sign Up</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif;
            display: flex;
            justify-content: center;
            align-items: center; }
        .wrapper{ width: 360px; padding: 20px; }
         
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Registration page</h2>
        <p>Please fill this form</p>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" class="form-control <?php echo (!empty($username_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $username; ?>">
                <span class="invalid-feedback"><?php echo $username_err; ?></span>
            </div>    
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" class="form-control <?php echo (!empty($password_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $password; ?>">
                <span class="invalid-feedback"><?php echo $password_err; ?></span>
            </div>
            <div class="form-group">
                <label>Confirm Password</label>
                <input type="password" name="confirm_password" class="form-control <?php echo (!empty($confirm_password_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $confirm_password; ?>">
                <span class="invalid-feedback"><?php echo $confirm_password_err; ?></span>
            </div>
            <div class="form-group ">
                <label>Mobile_Number</label><br>
                <input type="number" name="Mobile_Number" id="Mobile_Number" class="form-control <?php echo (!empty($Mobile_Number_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $Mobile_Number; ?>">
                <span class="invalid-feedback"><?php echo $Moblie_Number; ?></span>
            </div><br>
            <div class="form-group ">
                <label> Valid_Email</label>
                <input type="Email" name="Valid_Email" id="valid_Email" class="form-control <?php echo (!empty($Valid_Email_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $Valid_Email; ?>">
                <span class="invalid-feedback"><?php echo $Valid_Email; ?></span>
            </div><br>
            <div class="form-group ">
                <label> DATE_OF_BIRTH</label>
                <input type="date" name=" DATE_OF_BIRTH" id=" DATE_OF_BIRTH" class="form-control <?php echo (!empty($DATE_OF_BIRTH_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $DATE_OF_BIRTH; ?>">
                <span class="invalid-feedback"><?php echo $DATE_OF_BIRTH; ?></span>
            </div><br>
            <div class="Subject">SUBJECT :</div>
    <select class="form-control" >
        <option selected>Select Subject</option>
        <option value="1">Artificial intelligence</option>
        <option value="2">Rural Development</option>
        <option value="3">Cloud Computing</option>
        <option value="4">Universal Human Values</option>

      </select><br>
      <select class="form-control" >
        <option selected>Select Subject</option>
        <option value="1">Artificial intelligence</option>
        <option value="2">Rural Development</option>
        <option value="3">Cloud Computing</option>
        <option value="4">Universal Human Values</option>

      </select><br>
      <select class="form-control" >
        <option selected>Select Subject</option>
        <option value="1">Artificial intelligence</option>
        <option value="2">Rural Development</option>
        <option value="3">Cloud Computing</option>
        <option value="4">Universal Human Values</option>

      </select><br>
      <select class="form-control" >
        <option selected>Select Subject</option>
        <option value="1">Artificial intelligence</option>
        <option value="2">Rural Development</option>
        <option value="3">Cloud Computing</option>
        <option value="4">Universal Human Values</option>

      </select><br>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Submit">
                <input type="reset" class="btn btn-secondary ml-2" value="Reset">
            </div>
            <p>Already have an account? <a href="login.php">Login here</a>.</p>
        </form>
    </div>    
</body>
</html>
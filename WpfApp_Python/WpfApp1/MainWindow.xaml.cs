using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using WpfApp1.Controls;
using Microsoft.Win32;
using System.Timers;
using System.Windows.Threading;
using System.Threading;
using System.ComponentModel;
using System.Diagnostics;
using WpfApp1.View;
using WpfApp1.Model;
using WpfApp1.Controller;
using System.Drawing;
using Image = System.Drawing.Image;
using System.Threading.Tasks;
using System.Text.RegularExpressions;

namespace WpfApp1
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window , IScreenRemoteView , IMessagingAreaContainer
    {
        #region Private fields
        //Messages
        private const string m_csStartConnectMsg = "Start the connection";
        private const string m_csStopConnectMsg = "Stop the connection";
        private const string m_csCantStartConnectMsg = "Can't connect to guiconnector";

        //Events
        static ManualResetEvent manualResetEvent = new ManualResetEvent(false);

        //Constant Variables
        const int MINIMUM_LENGTH = 6;
        const int WAIT_TIME = 10000;
        const int SEND_REQUEST_WAIT_TIME = 17000;

        DispatcherTimer m_MessageTimer = null;
        ScreenRemoteController controller = null;
        /// <summary>
        /// List of open private chat windows.
        /// </summary>
        //private readonly SortedList<string, PrivateChatWindow> m_PrivateChatWindows;
        //public variables - results of requests
        public String _registrationHandlerResult = null;
        public String _loginHandlerResult = null;
        public String _connectionRequestHandlerResult = null;
        #endregion
        public string Email_Signup
        {
            get { return (string)Dispatcher.Invoke(new Func<string>(() => email_singup_textbox.Text)); }
            set { email_singup_textbox.Text = value; }
        }

        public string Username_Signup
        {
            get { return (string)Dispatcher.Invoke(new Func<string>(() => username_singup_textbox.Text)); }
            set { username_singup_textbox.Text = value; }
        }
        public string Password_Signup
        {
            get { return (string)Dispatcher.Invoke(new Func<string>(() => password_singup_textbox.Password)); }
            set { password_singup_textbox.Password = value; }
        }
        public string Email_Login
        {
            get { return (string)Dispatcher.Invoke(new Func<string>(() => login_email.Text)); }
            set { login_email.Text = value; }
        }

        public string Username_Login
        {
            get { return (string)Dispatcher.Invoke(new Func<string>(() => login_username.Text)); }
            set { login_username.Text = value; }
        }
        public string Password_Login
        {
            get { return (string)Dispatcher.Invoke(new Func<string>(() => login_password.Password)); }
            set { login_password.Password = value; }
        }
        public string Username_Connection_Request_Window
        {
            get { return (string)Dispatcher.Invoke(new Func<string>(() => Connection_Window_Username_Textbox.Text)); }
            set {Connection_Window_Username_Textbox.Text = value; }
        }
        public string UserName
        {
            get { return (string)Dispatcher.Invoke(new Func<string>(() => txtUserName.Text)); }
            set { txtUserName.Text = value; }
        }
        /// <summary>
        /// IP address of server to be connected.
        /// </summary>
        public string ServerIpAddress
        {
            get { return (string)Dispatcher.Invoke(new Func<string>(() => txtServerIpAddress.Text)); }
            set { txtServerIpAddress.Text = value; }

        }

        public void UpdateConnectionView(int iConnectStatus)
        {
            this.Dispatcher.BeginInvoke(new Action(() => SetConnectionView(iConnectStatus)), DispatcherPriority.Normal);
        }
        public void UpdateScreenMsgData(byte[] byteScreenData)
        {
            this.Dispatcher.Invoke(new Action(() => SetScreenMsgData(byteScreenData)), DispatcherPriority.Normal);
        }

        /**
        Sets the screen message data by converting a byte array into an image and updating the GUI.
        @param byteScreenData The byte array containing the image data.
        */
        protected void SetScreenMsgData(byte[] byteScreenData)
        {
            //Create Image from byte buffer
            try
            {
                MemoryStream stream = new MemoryStream(byteScreenData);
                BitmapImage image = new BitmapImage();
                image.BeginInit();
                image.StreamSource = stream;
                image.EndInit();
                //Update the GUI
                imgPicture.Source = null;
                imgPicture.Source = image;
                //imgPicture.Source = new BitmapImage(new Uri(sPicPath));
            }
            catch (Exception ex) // Catch all types of exceptions
            {
                Console.WriteLine("Exception: " + ex.Message);
            }



        }

        /**

        Updates the image displayed in the imgPicture control with the image located at the specified path.
        @param sPicPath The path of the image to be displayed.
        */
        private void UpdatePictureToControl(string sPicPath)
        {
            imgPicture.Source = null;
            imgPicture.Source = new BitmapImage(new Uri(sPicPath));
        }

        /**
        Updates the connection status view by setting the icon and login/logout button content based on the input status.
        @param iConnectStatus The connection status to be displayed (0 for disconnected, 1 for connected).
        */
        protected void SetConnectionView(int iConnectStatus)
        {
            //update the icon
            if (iConnectStatus == 1)
            {
                String sConnectedImage = Path.Combine((Path.Combine(Directory.GetCurrentDirectory(), @"Images\Network.png")));
                imgNetworkStatus.Source = new BitmapImage(new Uri(sConnectedImage));
                btnLogin.Content = "Logout     ";
                this.Remote_Control_Screen.Visibility = Visibility.Collapsed; //temp - for testing srt without srp
                this.initialConnectionGrid.Visibility = Visibility.Collapsed; //once gui binded to guiconnector it can't be unbinded
                this.LoginWindow.Visibility = Visibility.Visible; //temp - for testing srt without srp
            }
            else
            {
                String sDisConnectedImage = Path.Combine((Path.Combine(Directory.GetCurrentDirectory(), @"Images\Disconnection.png")));
                imgNetworkStatus.Source = new BitmapImage(new Uri(sDisConnectedImage));
                String msg = (iConnectStatus == 0) ? m_csStopConnectMsg : m_csCantStartConnectMsg;
                UpdateGUIMessage(msg, true);
                btnLogin.Content = "Login     ";
            }
        }
        /// <summary>
        /// TCP Port number of server to be connected.
        /// </summary>
        public int ServerPortID
        {
            get { return (int)Dispatcher.Invoke(new Func<int>(() => Convert.ToInt32(txtServerPort.Text))); }
            set { txtServerPort.Text = value.ToString(); }
        }


        #region IMessagingAreaContainer implementation

        /// <summary>
        /// Sends a message to the room.
        /// </summary>
        public void SendMessage(String sMessage)
        {
            controller.SendMsgdata(sMessage);
        }

        public void UpdateUserDataMsg(string sUserRemoteName, string sData)
        {
            //tota - add real nick name
            Dispatcher.BeginInvoke(new Action(() => messagingArea.MessageReceived(sUserRemoteName, sData)));
        }

        #endregion

        //#region Constructor and Initialize methods

        /// <summary>
        /// Creates a new form with a reference to the controller object.
        /// </summary>
        /// <param name="controller">Reference to the controller object</param>
        public MainWindow()
        {
            controller = new ScreenRemoteController(this);
            InitializeComponent();
            InitializeControls();
        }

        /**

        Handles the click event of the btnLogin button by calling either the ConnectMsg or DisconnectMsg method of the controller, depending on the button content.
        @param sender The object that raised the event.
        @param e The event arguments.
        */
        private void btnLogin_Click(object sender, RoutedEventArgs e)
        {
            String sBtnName = btnLogin.Content.ToString().TrimEnd(' ');

            if (sBtnName == "Login")
            {
                controller.ConnectMsg();
            }
            else
            {
                controller.DisconnectMsg();
            }
        }

        /// <summary>
        /// Initializes some controls.
        /// </summary>
        private void InitializeControls()
        {
            InitTimer();
            messagingArea.MessagingAreaContainer = this;
            UpdateGUIMessage("", false);
        }

        /**
        Updates the message displayed on the GUI by calling the SetMessageLabel method on the GUI thread.
        @param sMessage The message to be displayed.
        @param bEnable A flag indicating whether or not the GUI controls should be enabled.
        @param iWaitMilliSecond The number of milliseconds to wait before updating the GUI controls.
        */
        public void UpdateGUIMessage(string sMessage, bool bEnable, int iWaitMilliSecond = 1000)
        {
            this.Dispatcher.Invoke(new Action(() => SetMessageLabel(sMessage, bEnable, iWaitMilliSecond)), DispatcherPriority.Normal);
        }

        /**
        Sets the message label displayed on the GUI, and starts or stops a timer to control the visibility of the label.
        @param sMessage The message to be displayed.
        @param bEnable A flag indicating whether or not the GUI controls should be enabled.
        @param iWaitMilliSecond The number of milliseconds to wait before updating the GUI controls.
        */
        private void SetMessageLabel(string sMessage, bool bEnable, int iWaitMilliSecond)
        {
            if (bEnable == true)
            {
                gridMessage.Visibility = Visibility.Visible;
                labelMessageUser.Content = sMessage;
                m_MessageTimer.Interval = new TimeSpan(0, 0, 0, 0, iWaitMilliSecond);
                m_MessageTimer.Start();
            }
            else
            {
                gridMessage.Visibility = Visibility.Collapsed;
                labelMessageUser.Content = "";
                m_MessageTimer.Stop();
            }
        }

        /// <summary>
        /// Initialize the timer.
        /// </summary>
        void InitTimer()
        {
            m_MessageTimer = new DispatcherTimer(DispatcherPriority.ContextIdle, Dispatcher);
            m_MessageTimer.Interval = new TimeSpan(0, 0, 0, 0, 1500);
            m_MessageTimer.Tick += new EventHandler(timer_Elapsed2);
        }
        private void timer_Elapsed2(object o, EventArgs sender)
        {
            //After 1 second the message will disappear automatically
            UpdateGUIMessage("", false);
        }

      
        

        //        #region Handlers for events of window and controls

        /// <summary>
        /// Handles Loaded event of this Window.
        /// </summary>
        /// <param name="sender">Source of event</param>
        /// <param name="e">Event arguments</param>
        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            //txtName.Focus();
            //txtName.SelectAll();
        }

        /// <summary>
        /// Handles Closing event of this window.
        /// </summary>
        /// <param name="sender">Source of event</param>
        /// <param name="e">Event arguments</param>
        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
           // m_UserPreferences.Save();
           // m_Controller.Disconnect();
        }

        private void messagingArea_Loaded(object sender, RoutedEventArgs e)
        {

        }

        private void messagingArea_Loaded_1(object sender, RoutedEventArgs e)
        {

        }


        private void change_Window_To_Login(object sender, RoutedEventArgs e)
        {
            this.Sign_Up_Window.Visibility = Visibility.Collapsed;
            this.LoginWindow.Visibility = Visibility.Visible;
        }

        /// <summary>
        /// Event handler for the sign up button. Verifies the email format and minimum length of the email, username and password input fields before attempting to sign up the user. Calls the Sign_Up_Function in a new task if the input is valid. Displays success or failure message to the user based on the result of the sign up process.
        /// </summary>
        /// <param name="sender">The object that raised the event.</param>
        /// <param name="e">The event data.</param>
        private void Button_Sign_Up(object sender, RoutedEventArgs e)
        {
            this.signup_button.IsEnabled = false;
            this.Change_Window_To_Login_Button.IsEnabled = false;
            if (IsGmailFormat(this.email_singup_textbox.Text))
            {
                if (email_singup_textbox.Text.Length >= MINIMUM_LENGTH && username_singup_textbox.Text.Length >= MINIMUM_LENGTH && password_singup_textbox.Password.Length >= MINIMUM_LENGTH)
                {
                    Task task = Task.Factory.StartNew(() =>
                    {
                        Sign_Up_Function();
                    });
                }
                else
                {
                    UpdateGUIMessage("Entered data does not meet requirements!", true);
                }
            }
            else
            {
                UpdateGUIMessage("Email in bad format!", true);
            }
            this.signup_button.IsEnabled = true;
            this.Change_Window_To_Login_Button.IsEnabled = true;
        }

        /**
        Sends user signup information to the controller and waits for the registration handler result to be returned.
        Updates the GUI message to display the result of the registration attempt.
        */
        private void Sign_Up_Function()
        {
            this.controller.SendCustomMessage(Command.SET_EMAIL, Email_Signup);
            this.controller.SendCustomMessage(Command.SET_USER_NAME, Username_Signup);
            this.controller.SendCustomMessage(Command.SET_PASSWORD, Password_Signup);
            this.controller.SendCustomMessage(Command.REGISTRATION_HANDLER, null);
            manualResetEvent.WaitOne(WAIT_TIME);

            if (this._registrationHandlerResult == "1")
            {
                this.UpdateGUIMessage("Registration Successful!", true);

                Dispatcher.Invoke(new Action(() => this.LoginWindow.Visibility = Visibility.Visible), DispatcherPriority.Normal);
                Dispatcher.Invoke(new Action(() => this.Sign_Up_Window.Visibility = Visibility.Collapsed), DispatcherPriority.Normal);
                Dispatcher.Invoke(new Action(() => this.email_singup_textbox.Text = ""), DispatcherPriority.Normal);
                Dispatcher.Invoke(new Action(() => this.username_singup_textbox.Text = ""), DispatcherPriority.Normal);
                Dispatcher.Invoke(new Action(() => this.password_singup_textbox.Password = ""), DispatcherPriority.Normal);
            }
            else if (this._registrationHandlerResult == "0")
            {
                this.UpdateGUIMessage("Registration Failed!", true);
            }
            else
            {
                this.UpdateGUIMessage("Didn't Receive Result!", true);
            }
            //check success variable - move to new screen if received ok

            this._registrationHandlerResult = string.Empty;
            manualResetEvent.Reset(); //resetting event
        }

        /**
        Checks whether the given input string matches the format of a Gmail address.
        Returns true if the input matches the format, false otherwise.
        */
        private bool IsGmailFormat(string input)
        {
            // Regular expression for checking Gmail format
            string pattern = @"^[a-zA-Z0-9._%+-]+@gmail\.com$";
            Regex regex = new Regex(pattern);
            return regex.IsMatch(input);
        }

        /**
        This function is triggered when the user clicks on the login button.
        It first disables the login button and the change window to signup button to prevent multiple requests.
        It then checks if the entered email is in valid Gmail format.
        If the email is in valid format, it checks if the entered email, password and username meet the minimum length requirements.
        If the entered data meets the requirements, the Login_Function is called in a separate task.
        If the entered data does not meet the requirements, an error message is displayed.
        If the email is not in valid format, an error message is displayed.
        After the execution is complete, the login button and the change window to signup button are enabled again.
        */
        private void Login_Button_Click(object sender, RoutedEventArgs e)
        {
            this.login_button.IsEnabled = false;
            this.Change_Window_To_Signup_Button.IsEnabled = false;
            //send info and signup
            if (IsGmailFormat(this.login_email.Text))
            {
                if (login_email.Text.Length >= MINIMUM_LENGTH && login_password.Password.Length >= MINIMUM_LENGTH && login_username.Text.Length >= MINIMUM_LENGTH)
                {
                    Task task = Task.Factory.StartNew(() =>
                    {
                        Login_Function();
                    });
                }
                else
                {
                    UpdateGUIMessage("Entered data does not meet requirements!", true);
                }
            }
            else
            {
                UpdateGUIMessage("Email in bad format!", true);
            }

            this.login_button.IsEnabled = true;
            this.Change_Window_To_Signup_Button.IsEnabled = true;

        }

        /**
        This function is responsible for sending the email, username, and password entered by the user to the server for verification.
        It then waits for the server response for a specified time period before proceeding to check the response result.
        If the response result is "1", which means the login was successful, it displays a success message and navigates to the connection window, hiding the login window.
        If the response result is "0", which means the login failed, it displays a failure message.
        If the response result is anything else, it displays an error message.
        After the execution is complete, the _loginHandlerResult variable is reset to an empty string, and the manualResetEvent is reset.
        */
        private void Login_Function()
        {
            this.controller.SendCustomMessage(Command.SET_EMAIL, Email_Login);
            this.controller.SendCustomMessage(Command.SET_USER_NAME, Username_Login);
            this.controller.SendCustomMessage(Command.SET_PASSWORD, Password_Login);
            this.controller.SendCustomMessage(Command.VERIFICATION_HANDLER, null); 
            //need to make sure login is turned into one function
            manualResetEvent.WaitOne(WAIT_TIME);
            //check success variable - move to new screen if received ok
            if (this._loginHandlerResult == "1") // true
            {
                this.UpdateGUIMessage("Login Successful!", true);
                Dispatcher.Invoke(new Action(() => this.Connection_Window_Username.Content = Username_Login), DispatcherPriority.Normal);
                Dispatcher.Invoke(new Action(() => this.Connection_window.Visibility = Visibility.Visible), DispatcherPriority.Normal);
                Dispatcher.Invoke(new Action(() => this.LoginWindow.Visibility = Visibility.Collapsed), DispatcherPriority.Normal);
            }
            else if (this._loginHandlerResult == "0") // false
            {
                this.UpdateGUIMessage("Login Failed!", true);
            }
            else
            {
                this.UpdateGUIMessage("Didn't Receive Result!", true);
            }
            this._loginHandlerResult = String.Empty;
            manualResetEvent.Reset();
        }

        private void change_Window_To_Signup(object sender, RoutedEventArgs e)
        {
            this.LoginWindow.Visibility = Visibility.Collapsed;
            this.Sign_Up_Window.Visibility = Visibility.Visible;
        }

        /**
        This function is triggered when the user clicks on the Send Connection Request button.
        It first disables the Send Connection Request button, Logout button, and Listening button to prevent multiple requests.
        It then checks if the entered username meets the minimum length requirements.
        If the entered data meets the requirements, the Send_Connection_Request_Function is called in a separate task.
        If the entered data does not meet the requirements, an error message is displayed.
        After the execution is complete, the Send Connection Request button, Logout button, and Listening button are enabled again.
        */
        private void Send_Connection_Request_Button(object sender, RoutedEventArgs e)
        {
            //stopping button from being able to be clicked
            connection_button.IsEnabled = false;
            Logout_Button.IsEnabled = false;
            Listening_Button.IsEnabled = false;
            if (Connection_Window_Username_Textbox.Text.Length >= MINIMUM_LENGTH)
            {
                Task task = Task.Factory.StartNew(() =>
                {
                    Send_Connection_Request_Function();
                });
            }
            else
            {
                UpdateGUIMessage("Entered data does not meet requirements!", true);

            }
            connection_button.IsEnabled = true;
            Logout_Button.IsEnabled = true;
            Listening_Button.IsEnabled = true;

        }

        /**

        This function is responsible for sending a connection request to the server with the username entered by the user.
        It then waits for the server response for a specified time period before proceeding to check the response result.
        If the response result is "1", which means the connection request was accepted, it sends a command to run the connector, displays a success message, and navigates to the remote control screen, hiding the connection window.
        If the response result is "0", which means the connection request was denied, it displays a failure message.
        If the response result is anything else, it displays an error message.
        After the execution is complete, the _connectionRequestHandlerResult variable is reset to an empty string, and the manualResetEvent is reset.
        */
        private void Send_Connection_Request_Function()
        {
            this.controller.SendCustomMessage(Command.IP_REQUEST_HANDLER, Username_Connection_Request_Window);
            manualResetEvent.WaitOne(SEND_REQUEST_WAIT_TIME);
            //WAIT FOR RESPONSE
            if (this._connectionRequestHandlerResult == "1")
            {
                //receive ip and set it
                this.controller.SendCustomMessage(Command.RUN_CONNECTOR, "");
                UpdateGUIMessage("Starting the connection as connector...", true);
                Dispatcher.Invoke(new Action(() => this.Remote_Control_Screen.Visibility = Visibility.Visible), DispatcherPriority.Normal);
                Dispatcher.Invoke(new Action(() => this.Connection_window.Visibility = Visibility.Collapsed), DispatcherPriority.Normal);
            }
            else if (this._connectionRequestHandlerResult == "0")
            {
                UpdateGUIMessage("Connection request was denied!", true);
            }
            else
            {
                UpdateGUIMessage("Didn't Receive Result!", true);
            }
            this._connectionRequestHandlerResult = String.Empty;
            manualResetEvent.Reset();
            this._connectionRequestHandlerResult = String.Empty;
        }

        /**

        This function is triggered when the user clicks on the Logout button.
        It first disables the Send Connection Request button, Logout button, Listening button, and Delete Account button to prevent multiple requests.
        It then calls the Logout_Function in a separate task to handle the logout process.
        After the execution is complete, the Send Connection Request button, Logout button, Listening button, and Delete Account button are enabled again.
        */
        private void Logout_Button_Click(object sender, RoutedEventArgs e)
        {
            connection_button.IsEnabled = false;
            Logout_Button.IsEnabled = false;
            Listening_Button.IsEnabled = false;
            Delete_Account_Button.IsEnabled = false;
            Task task = Task.Factory.StartNew(() =>
            {
                Logout_Function();
            });
            connection_button.IsEnabled = true;
            Logout_Button.IsEnabled = true;
            Listening_Button.IsEnabled = true;
            Delete_Account_Button.IsEnabled = true;

        }

        /**

        This function is called by the Logout_Button_Click function to handle the logout process.
        It sends a custom message with the sign out command to the controller, then waits for a response using a manual reset event.
        If the response received is "1", it means that the logout was successful and the user is redirected to the LoginWindow.
        If the response received is "0", it means that the logout failed.
        If no response is received, it means that something went wrong.
        The function resets the manual reset event and the _loginHandlerResult variable for future use.
        */
        private void Logout_Function()
        {
            this.controller.SendCustomMessage(Command.SIGN_OUT, "");
            manualResetEvent.WaitOne(WAIT_TIME);
            if(this._loginHandlerResult == "1")
            {
                Dispatcher.Invoke(new Action(() => this.Connection_window.Visibility = Visibility.Collapsed), DispatcherPriority.Normal);
                Dispatcher.Invoke(new Action(() => this.LoginWindow.Visibility = Visibility.Visible), DispatcherPriority.Normal);
                UpdateGUIMessage("Logout Successful!",true);
            }
            else if(this._loginHandlerResult == "0")
            {
                UpdateGUIMessage("Logout Failed!", true);
            }
            else
            {
                UpdateGUIMessage("Didn't Receive Result!", true);
            }
            manualResetEvent.Reset();
            this._loginHandlerResult = String.Empty;
        }

        /**

        This method is called when the "Delete Account" button is clicked. It disables all other buttons to prevent
        user input, then starts a new task to execute the Delete_Account_Function. Once the task is complete, it
        re-enables the buttons.
        @param sender The object that triggered the event.
        @param e The event arguments associated with the event.
        @return void
        */
        private void Delete_Account_Button_Click(object sender, RoutedEventArgs e)
        {
            connection_button.IsEnabled = false;
            Logout_Button.IsEnabled = false;
            Delete_Account_Button.IsEnabled = false;
            Listening_Button.IsEnabled = false;
            Task task = Task.Factory.StartNew(() =>
            {
                Delete_Account_Function();
            });
            connection_button.IsEnabled = true;
            Logout_Button.IsEnabled = true;
            Listening_Button.IsEnabled = true;
            Delete_Account_Button.IsEnabled = true;

        }

        /**
        This method sends a DELETE_ACCOUNT command to the server using the controller, and waits for a response from the
        server. Once a response is received, it updates the GUI with a success or failure message depending on the result.
        @return void
        */
        private void Delete_Account_Function()
        {
            this.controller.SendCustomMessage(Command.DELETE_ACCOUNT, "");
            manualResetEvent.WaitOne(WAIT_TIME);
            if (this._loginHandlerResult == "1")
            {
                Dispatcher.Invoke(new Action(() => this.Connection_window.Visibility = Visibility.Collapsed), DispatcherPriority.Normal);
                Dispatcher.Invoke(new Action(() => this.LoginWindow.Visibility = Visibility.Visible), DispatcherPriority.Normal);
                UpdateGUIMessage("Delete Successful!", true);
            }
            else if (this._loginHandlerResult == "0")
            {
                UpdateGUIMessage("Delete Failed!", true);
            }
            else
            {
                UpdateGUIMessage("Didn't Receive Result!", true);
            }
            manualResetEvent.Reset();
            this._loginHandlerResult = String.Empty;
        }

        /**

        This method is called when the "Allow Connection" button is clicked. It disables both the "Allow Connection" and
        "Deny Connection" buttons, then starts a new task to execute the Allow_Connection_Function. Once the task is
        complete, it re-enables the buttons.
        @param sender The object that triggered the event.
        @param e The event arguments associated with the event.
        @return void
        */
        private void Allow_Connection_Button(object sender, RoutedEventArgs e)
        {
            this.allow_button.IsEnabled = false;
            this.deny_button.IsEnabled = false;
            Task task = Task.Factory.StartNew(() =>
            {
                Allow_Connection_Function();
            });
            this.allow_button.IsEnabled = true;
            this.deny_button.IsEnabled = true;
        }

        /**

        This method sends an ALLOW_CONNECTION_REQUEST command to the server using the controller, and waits for a response
        from the server. If the response is positive, it sends a RUN_HOST command to start the connection as a host, and
        updates the GUI accordingly. If the response is negative or no response is received, it updates the GUI with a
        failure message.
        @return void
        */
        private void Allow_Connection_Function()
        {
            this.controller.SendCustomMessage(Command.ALLOW_CONNECTION_REQUEST, "");
            manualResetEvent.WaitOne(WAIT_TIME);
            if (this._loginHandlerResult == "1")
            {
                this.controller.SendCustomMessage(Command.RUN_HOST, "");
                Dispatcher.Invoke(new Action(() => this.Remote_Control_Screen.Visibility = Visibility.Visible), DispatcherPriority.Normal);
                Dispatcher.Invoke(new Action(() => this.Connection_Request_Window.Visibility = Visibility.Collapsed), DispatcherPriority.Normal);
                Dispatcher.Invoke(new Action(() => this.Connection_Listening_Window.Visibility = Visibility.Collapsed), DispatcherPriority.Normal);
                Dispatcher.Invoke(new Action(() => this.Connection_window.Visibility = Visibility.Collapsed), DispatcherPriority.Normal);
                UpdateGUIMessage("Starting the connection as host...", true);
            }
            else if (this._loginHandlerResult == "0")
            {
                UpdateGUIMessage("Failed To Accept Request!", true);
                Dispatcher.Invoke(new Action(() => this.Connection_Request_Window.Visibility = Visibility.Collapsed), DispatcherPriority.Normal);
            }
            else
            {
                UpdateGUIMessage("Didn't Receive Result!", true);
                Dispatcher.Invoke(new Action(() => this.Connection_Request_Window.Visibility = Visibility.Collapsed), DispatcherPriority.Normal);
            }
            manualResetEvent.Reset();
            this._loginHandlerResult = String.Empty;
        }

        /**

        This method is called when the "Deny Connection" button is clicked. It disables both the "Allow Connection" and
        "Deny Connection" buttons, then hides the Connection_Request_Window. Once the window is hidden, it re-enables the
        buttons.
        @param sender The object that triggered the event.
        @param e The event arguments associated with the event.
        @return void
        */
        private void Deny_Connection_Button(object sender, RoutedEventArgs e)
        {
            this.allow_button.IsEnabled = false;
            this.deny_button.IsEnabled = false;
            this.Connection_Request_Window.Visibility= Visibility.Collapsed;
            this.allow_button.IsEnabled = true;
            this.deny_button.IsEnabled = true;
        }

        public void UpdateRegistrationResult(String result)
        {
            this._registrationHandlerResult = result;
            manualResetEvent.Set();
        }
        public void UpdateLoginResult(String result)
        {
            this._loginHandlerResult = result;
            manualResetEvent.Set();
        }
        public void UpdateConnectionRequestResult(String result)
        {
            this._connectionRequestHandlerResult = result;
            manualResetEvent.Set();
        }

        /**

        This method is called when the user clicks the "Cancel" button while waiting for connection requests. It disables
        several buttons to prevent further user interaction, then starts a new task to execute the
        Cancel_Waiting_For_Requests_Function. Once the task is complete, it re-enables the buttons.
        @param sender The object that triggered the event.
        @param e The event arguments associated with the event.
        @return void
        */
        private void Cancel_Waiting_For_Requests (object sender, RoutedEventArgs e)
        {
            connection_button.IsEnabled = false;
            Logout_Button.IsEnabled = false;
            Delete_Account_Button.IsEnabled = false;
            Listening_Button.IsEnabled = false;
            Task task = Task.Factory.StartNew(() =>
            {
                Cancel_Waiting_For_Requests_Function();
            });
            connection_button.IsEnabled = true;
            Logout_Button.IsEnabled = true;
            Listening_Button.IsEnabled = true;
            Delete_Account_Button.IsEnabled = true;
        }

        /**

        This method is responsible for handling the "Cancel" button click event when the user is waiting for connection
        requests. It sends a custom message to the server to stop listening for connection requests, then waits for a
        response. Once a response is received, it hides the Connection_Listening_Window and updates the GUI with the
        appropriate message. If an error occurs, it updates the GUI with an error message.
        @return void
        */
        private void Cancel_Waiting_For_Requests_Function()
        {
            this.controller.SendCustomMessage(Command.STOP_LISTENING_FOR_REQUESTS, "");
            manualResetEvent.WaitOne(WAIT_TIME);
            if (this._loginHandlerResult == "1")
            {
                Dispatcher.Invoke(new Action(() => this.Connection_Listening_Window.Visibility = Visibility.Collapsed), DispatcherPriority.Normal);
                UpdateGUIMessage("Stopped Listening!", true);
            }
            else if (this._loginHandlerResult == "0")
            {
                UpdateGUIMessage("Failed To Stop Listening!", true);
            }
            else
            {
                UpdateGUIMessage("Didn't Receive Result!", true);
            }
            manualResetEvent.Reset();
            this._loginHandlerResult = String.Empty;
        }

        /**

        This method is responsible for handling the "Listen" button click event when the user wants to listen for connection
        requests. It disables other buttons, starts a new Task to call Listen_For_Requests_Function, then enables the buttons
        once the Task is completed.
        @return void
        */
        private void Listen_For_Requests(object sender, RoutedEventArgs e)
        {
            connection_button.IsEnabled = false;
            Logout_Button.IsEnabled = false;
            Delete_Account_Button.IsEnabled = false;
            Listening_Button.IsEnabled = false;
            Task task = Task.Factory.StartNew(() =>
            {
                Listen_For_Requests_Function();
            });
            connection_button.IsEnabled = true;
            Logout_Button.IsEnabled = true;
            Listening_Button.IsEnabled = true;
            Delete_Account_Button.IsEnabled = true;
        }

        /**
        Listen_For_Requests_Function method:
        Listens for incoming requests and starts the connection listening window
        This method sends a custom message to the controller to start listening for incoming requests
        and waits for a response using a ManualResetEvent with a timeout period.
        If the login handler result is "1", the Connection_Listening_Window is set to visible and
        a message is displayed in the GUI indicating that listening has started. If the login handler result is "0",
        a message is displayed in the GUI indicating that listening failed to start. If the login handler result is
        anything other than "1" or "0", a message is displayed in the GUI indicating that a result was not received.
        @access private
        @return void
        */
        private void Listen_For_Requests_Function()
        {
            this.controller.SendCustomMessage(Command.START_LISTENING, "");
            manualResetEvent.WaitOne(WAIT_TIME);
            if (this._loginHandlerResult == "1")
            {
                Dispatcher.Invoke(new Action(() => this.Connection_Listening_Window.Visibility = Visibility.Visible), DispatcherPriority.Normal);
                UpdateGUIMessage("Started Listening!", true);
            }
            else if (this._loginHandlerResult == "0")
            {
                UpdateGUIMessage("Failed To Start Listening!", true);
            }
            else
            {
                UpdateGUIMessage("Didn't Receive Result!", true);
            }
            manualResetEvent.Reset();
            this._loginHandlerResult = String.Empty;
        }


        public void UpdateClientWithReceivedRequest(string requesting_user_name)
        {
            Dispatcher.Invoke(new Action(() => this.Connection_Request_Window_Username.Text = requesting_user_name), DispatcherPriority.Normal);
            Dispatcher.Invoke(new Action(() => this.Connection_Request_Window.Visibility = Visibility.Visible), DispatcherPriority.Normal);
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            this.Remote_Control_Screen.Visibility = Visibility.Collapsed; //temp - for testing srt without srp
            this.LoginWindow.Visibility = Visibility.Visible; //temp - for testing srt without srp
            this.srp_button.Visibility = Visibility.Collapsed;
            this.srt_connector_button.Visibility = Visibility.Collapsed;
            this.srt_host_button.Visibility = Visibility.Collapsed;
        }

        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            this.controller.SendCustomMessage(Command.RUN_HOST, "this.ip_for_srt.Text");
            this.srt_connector_button.Visibility = Visibility.Collapsed;
            this.srt_host_button.Visibility = Visibility.Collapsed;

        }
        private void Button_Click_2(object sender, RoutedEventArgs e)
        {
            this.controller.SendCustomMessage(Command.RUN_CONNECTOR, "this.ip_for_srt.Text");
            this.srt_connector_button.Visibility = Visibility.Collapsed;
            this.srt_host_button.Visibility = Visibility.Collapsed;

        }

    }
}

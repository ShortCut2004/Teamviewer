using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Packaging;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Permissions;
using System.Security.Policy;
using System.Text;
using System.Threading;
using System.Windows.Documents;
using System.Windows.Media.Imaging;

namespace WpfApp1.Model
{
    public class ScreenRemoteModel : IScreenRemoteModel
    {
        public String UserName { get; set; }
        public String UserRemoteName { get; set; }
        public bool IsConnect { get; set; }
        public Socket m_clientSocket;
        public int ClientPortID { get; set; }
        public String ClientIPAddress { get; set; }

        private byte[] byteArrData = new byte[2000000];


        //Queue MPEG message
        public Thread m_threadSaveImages = null;
        public bool m_fCloseThread = false;
        public ConcurrentQueue<byte[]> m_safeRecivedScreenMessage = new ConcurrentQueue<byte[]>();

        //Events
        public event SendMsgUserData msgUserDataEvent;
        public event SendGUIUpdateData msgUpdateGUIData;
        public event SendConnectionStatus msgConnectionStatus;
        public event SendRecivedScreenData msgRecivedScreenData;
        public event SendRegistrationHandlerResult msgRegistrationHandlerResult;
        public event SendLoginHandlerResult msgLoginHandlerResult;
        public event SendConnectionRequestResult msgConnectionRequestResult;
        public event SendReceivedConnectionRequest msgReceivedConnectionRequest;

        /// <summary>
        /// 
        /// </summary>
        public ScreenRemoteModel()
        {
            m_clientSocket = null;
            ClientPortID = 0;
            IsConnect = false;
        }

        public void Init()
        {
            try
            {
                Console.WriteLine("not implemented");
            }
            catch(Exception ex)
            {
                Trace.WriteLine(ex.Message);
            }
        }

        /// <summary>
        /// The function connects the socket to the entered port and ip
        /// </summary>
        /// <param name="sUserName"></param>
        /// <param name="sIpAddress"></param>
        /// <param name="iPordID"></param>
        /// <returns></returns>
        public bool Connect(String sUserName, String sIpAddress, int iPordID)
        {
            bool bRetVal = false;

            try
            {
                m_clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                //m_UDPMessageSender = new UdpClient();
                Debug.Assert(m_clientSocket != null);

                UserName = sUserName;
                ClientPortID = iPordID;
                ClientIPAddress = sIpAddress;
                IPAddress ip = IPAddress.Parse(sIpAddress);
                IPEndPoint ipEnd = new IPEndPoint(ip, iPordID);
                //m_clientSocket.Connect(ipEnd);
                m_clientSocket.BeginConnect(ipEnd, new AsyncCallback(ReceiveConnectCallback), null);
                bRetVal = true;
            }
            catch (SocketException ex)
            {
                Debug.Write("Critical error occurred while trying to open the UDP connection - [%s]", ex.Message);
            }

            return bRetVal;
        }
        /// <summary>
        /// call back for connect function
        /// </summary>
        /// <param name="ar"></param>
        private void ReceiveConnectCallback(IAsyncResult ar)
        {
            try
            {
                m_clientSocket.EndConnect(ar);

                //We are connected so we login into the server
                DataMessage msgToSend = new DataMessage();
                msgToSend.DataCommandType = Command.login;
                msgToSend.UserName = UserName;
                msgToSend.MessageData = null;

                byte[] byteData = msgToSend.ToByte();
                //Send the message to the server
                m_clientSocket.BeginSend(byteData, 0, byteData.Length, SocketFlags.None, new AsyncCallback(SendMsgCallback), null);
                IsConnect = true;
                ThreadHandleScreenMsg();

                if (msgConnectionStatus != null)
                {
                    msgConnectionStatus(this, IsConnect ? 1 : 0);
                }
                //Start listening to the data asynchronously
                WaitForData();
            }
            catch (SocketException ex)
            {
                Trace.Write(ex.Message);
                if (msgConnectionStatus != null)
                {
                    msgConnectionStatus(this, 2); //mean faiulre
                }
            }
        }

        /// <summary>
        /// call back for send message function
        /// </summary>
        /// <param name="ar"></param>
        private void SendMsgCallback(IAsyncResult ar)
        {
            try
            {
                m_clientSocket.EndSend(ar);
            }
            catch (SocketException ex)
            {
                Trace.Write(ex.Message);
            }
        }
        /// <summary>
        /// call back for messsage received case
        /// </summary>
        /// <param name="ar"></param>
        private void ReceiveMsgCallback(IAsyncResult ar)
        {
            try
            {
                if ((m_clientSocket == null) || (m_clientSocket.Connected == false) || (IsConnect == false))
                {
                    Trace.Write("Socket connection has been closed !!!");
                    IsConnect = false;
                    if (msgConnectionStatus != null)
                    {
                        msgConnectionStatus(this, IsConnect ? 1 : 0);
                    }
                    return;
                }

                //End receive...
                int iRecievedByte = m_clientSocket.EndReceive(ar);
                DataMessage msgReceived = new DataMessage(byteArrData);

                //Accordingly process the message received
                switch (msgReceived.DataCommandType)
                {
                    case Command.login:
                        {
                            UserRemoteName = msgReceived.UserName;
                            string receiveString = String.Format("Start connection...");
                            Trace.WriteLine("Received: {0}", receiveString);
                            if (msgUserDataEvent != null)
                            {
                                msgUserDataEvent(this, receiveString);
                            }
                            break;
                        }

                    case Command.logout:
                        //tota for testing
                        if (false) 
                        {
                            String sImage = Path.Combine((Path.Combine(Directory.GetCurrentDirectory(), @"Images\try.jpeg")));
                            BitmapImage imageIn = new BitmapImage(new Uri(sImage));

                            byte[] buf1 = null;
                            JpegBitmapEncoder encoder = new JpegBitmapEncoder();
                            encoder.Frames.Add(BitmapFrame.Create(imageIn));
                            using (MemoryStream ms = new MemoryStream())
                            {
                                encoder.Save(ms);
                                buf1 = ms.ToArray();
                            }
                            m_safeRecivedScreenMessage.Enqueue(buf1);
                        }

                        break;

                    case Command.Message:
                        if ((msgUserDataEvent != null) && (msgReceived.MessageData != null))
                        {
                            msgUserDataEvent(this, msgReceived.MessageData);
                        }
                        break;

                    case Command.ScreenMsg:
                        byte[] buf = new byte[msgReceived.ScreenArrayData.Length];
                        Buffer.BlockCopy(msgReceived.ScreenArrayData, 0, buf, 0, msgReceived.ScreenArrayData.Length);
                        m_safeRecivedScreenMessage.Enqueue(buf);
                        break;

                    case Command.ERROR:
                        if (msgUpdateGUIData != null)
                        {
                            msgUpdateGUIData(this, msgReceived.MessageData);
                        }
                        break;
                    case Command.REGISTRATION_HANDLER:
                        if (msgRegistrationHandlerResult != null)
                        {
                            msgRegistrationHandlerResult(this, msgReceived.MessageData);
                        }
                        break;
                    case Command.VERIFICATION_HANDLER:
                        if (msgLoginHandlerResult != null)
                        {
                            msgLoginHandlerResult(this, msgReceived.MessageData);
                        }
                        break;
                    case Command.SIGN_OUT:
                        if (msgLoginHandlerResult != null)
                        {
                            msgLoginHandlerResult(this, msgReceived.MessageData);
                        }
                        break;
                    case Command.DELETE_ACCOUNT:
                        if (msgLoginHandlerResult != null)
                        {
                            msgLoginHandlerResult(this, msgReceived.MessageData);
                        }
                        break;
                    case Command.IP_REQUEST_HANDLER:
                        if (msgConnectionRequestResult != null)
                        {
                            msgConnectionRequestResult(this, msgReceived.MessageData);
                        }
                        break;
                    case Command.IP_RESPONSE_PEER_HANDLER:
                        if (msgReceivedConnectionRequest != null)
                        {
                            msgReceivedConnectionRequest(this, msgReceived.MessageData); //sending the username of the client who requested connection
                        }
                        break;
                    case Command.START_LISTENING:
                        if (msgLoginHandlerResult != null)
                        {
                            msgLoginHandlerResult(this, msgReceived.MessageData);
                        }
                        break;
                    case Command.STOP_LISTENING_FOR_REQUESTS:
                        if (msgLoginHandlerResult != null)
                        {
                            msgLoginHandlerResult(this, msgReceived.MessageData);
                        }
                        break;
                    case Command.ALLOW_CONNECTION_REQUEST:
                        if (msgLoginHandlerResult != null)
                        {
                            msgLoginHandlerResult(this, msgReceived.MessageData);
                        }
                        break;
                    //Should never reach here
                    default:
                        //Debug.Assert(false);
                        break;
                }

                //trigger to continue for data
                WaitForData();
            }
            catch (SocketException ex)
            {
                Trace.Write(ex.Message);
            }
        }

        private void WaitForData()
        {
            try
            {
                byteArrData = new byte[2000000];
                // now start to listen for any data...
                m_clientSocket.BeginReceive(byteArrData, 0, byteArrData.Length, SocketFlags.None, new AsyncCallback(ReceiveMsgCallback), null);
            }
            catch (SocketException ex)
            {
                Trace.WriteLine(ex.Message);
            }
        }

        /**

        DisConnect method:
        Disconnects the client socket from the server and logs out the user
        This method checks if the client socket is connected to the server and sends a logout message
        to the server to log out the user. It then closes and disposes of the client socket and sets
        the IsConnect flag to false. If an error occurs, it catches the SocketException, closes and disposes
        the client socket, sets the IsConnect flag to false, and calls the msgConnectionStatus event with a
        status of 0 to indicate that the connection has been lost.
        @access public
        @return void
        */
        public void DisConnect()
        {
            try
            {
                if ((IsConnect == false) || (m_clientSocket == null))
                {
                    if (msgConnectionStatus != null)
                    {
                        msgConnectionStatus(this, 0);
                    }
                    return;
                }

                //Send a message to logout of the server
                DataMessage msgToSend = new DataMessage();
                msgToSend.DataCommandType = Command.logout;
                msgToSend.UserName = UserName;
                msgToSend.MessageData = null;

                byte[] byteData = msgToSend.ToByte();
                m_clientSocket.Send(byteData, 0, byteData.Length, SocketFlags.None);

                IsConnect = false;
                if (msgConnectionStatus != null)
                {
                    msgConnectionStatus(this, IsConnect ? 1 : 0);
                }

                m_clientSocket.Close();
                m_clientSocket.Dispose();
                m_clientSocket = null;
                m_fCloseThread = true;

                WaitForEmptyTheSafeQueue();
            }
            catch (SocketException ex)
            {
                Trace.WriteLine(ex.Message);
                m_clientSocket.Close();
                m_clientSocket.Dispose();
                m_clientSocket = null;
                m_fCloseThread = true;
                IsConnect = false;
                if (msgConnectionStatus != null)
                {
                    msgConnectionStatus(this, 0);
                }
            }
        }

        /**

        SendMsgData method:
        Sends a message to the server
        This method creates a DataMessage object with the provided message and sends it to the server
        using the client socket's BeginSend method with a callback function SendMsgCallback. If an error
        occurs, it catches the SocketException and writes a message to the Trace output. The method always
        returns true.
        @access public
        @param sMessage The message to be sent
        @return bool Always returns true
        */
        public bool SendMsgData(String sMessage)
        {
            try
            {
                //Fill the info for the message to be send
                DataMessage msgToSend = new DataMessage();

                msgToSend.UserName = UserName;
                msgToSend.MessageData = sMessage;
                msgToSend.DataCommandType = Command.Message;

                byte[] byteData = msgToSend.ToByte();

                //Send it to the server
                m_clientSocket.BeginSend(byteData, 0, byteData.Length, SocketFlags.None, new AsyncCallback(SendMsgCallback), null);
            }
            catch (SocketException ex)
            {
                Trace.WriteLine(ex.Message);
            }

            return true;
        }

        /**

        SendCustomMessage method:
        Sends a custom message to the server
        This method creates a DataMessage object with the provided command and message and sends it to the
        server using the client socket's BeginSend method with a callback function SendMsgCallback. If an error
        occurs, it catches the SocketException and writes a message to the Trace output. The method always
        returns true.
        @access public
        @param command The command to be sent
        @param sMessage The message to be sent
        @return bool Always returns true
        */
        public bool SendCustomMessage(Command command, String sMessage)
        {
            try
            {
                //Fill the info for the message to be send
                DataMessage msgToSend = new DataMessage();

                msgToSend.UserName = UserName;
                msgToSend.MessageData = sMessage;
                msgToSend.DataCommandType = command;

                byte[] byteData = msgToSend.ToByte();

                //Send it to the server
                m_clientSocket.BeginSend(byteData, 0, byteData.Length, SocketFlags.None, new AsyncCallback(SendMsgCallback), null);
            }
            catch (SocketException ex)
            {
                Trace.WriteLine(ex.Message);
            }

            return true;
        }
        //JPEG Queue functions
        //====================

        /**

        ThreadHandleScreenMsg method:
        Handles the thread that saves screen messages
        This method creates a thread to handle saving screen messages by checking if m_threadSaveImages
        is null. If it is, it sets m_fCloseThread to false, creates a new thread with the method
        ThreadFuncSaveScreenMsg, sets its priority to normal, starts it and returns true. Otherwise, it
        simply returns false.
        @access public
        @return bool True if a new thread is created, otherwise false
        */
        public bool ThreadHandleScreenMsg()
        {
            bool fCreateThread = false;

            if (m_threadSaveImages == null)
            {
                m_fCloseThread = false;
                m_threadSaveImages = new Thread(new ThreadStart(ThreadFuncSaveScreenMsg));
                m_threadSaveImages.Priority = ThreadPriority.Normal;
                //m_threadSaveLogToFile.Name = m_threadSaveLogToFile.ManagedThreadId;
                m_threadSaveImages.Start();
                fCreateThread = true;
            }

            return fCreateThread;
        }
        /**

        ThreadFuncSaveScreenMsg method:
        Function that handles saving screen messages in a thread.
        This method is responsible for saving screen messages in a separate thread. It continuously checks
        for messages in the m_safeRecivedScreenMessage queue while m_fCloseThread is false and m_clientSocket
        is not null. If a message is found in the queue, it is dequeued and passed to the HandleMessageAsBytes
        method for processing. If an exception is thrown during execution, a trace message is written.
        @access public
        @return void
        */
        public void ThreadFuncSaveScreenMsg()
        {
            try
            {
                byte[] barBuf = null;
                while ((m_fCloseThread == false) && (m_clientSocket != null))
                {
                    Thread.Sleep(1);
                    barBuf = null;

                    if (m_safeRecivedScreenMessage.TryDequeue(out barBuf) == true) // get the first element from the queue and remove it from the queue
                    {
                        HandleMessageAsBytes(barBuf);
                    }
                }

                m_fCloseThread = false;
                m_threadSaveImages = null;
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex.Message);
            }
        }

        /// <summary>
        /// Send the arrived message to all registered events 
        /// </summary>
        /// <param name="barBuffer">the data message in a string format</param>
        private void HandleMessageAsBytes(byte[] barBuffer)
        {
            if (msgRecivedScreenData != null)
            {
                msgRecivedScreenData(this, barBuffer);
            }
        }


        /// <summary>
        /// 
        /// </summary>
        public void WaitForEmptyTheSafeQueue()
        {
            if (m_threadSaveImages != null)
            {
                // now close the thread
                m_fCloseThread = true;
                Thread.Sleep(10);
                int iLoop = 0;
                while (m_threadSaveImages != null)
                {
                    // wait for finishing writing to file, it happens for some reason that it looks here and not exist
                    // so I added a timeout to be on the safe side
                    Thread.Sleep(10);
                    iLoop++;
                    if (iLoop > 20) // if passed 2 seconds
                    {
                        KillTheThreadSaveLogToFile();
                        m_threadSaveImages = null; // cause to exit the thread
                    }
                }
            }
        }


        [SecurityPermissionAttribute(SecurityAction.Demand, ControlThread = true)]
        private void KillTheThreadSaveLogToFile()
        {
            m_threadSaveImages.Abort();
            m_threadSaveImages = null;
        }
    }
}

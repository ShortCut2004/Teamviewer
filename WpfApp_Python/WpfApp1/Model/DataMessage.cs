using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WpfApp1.Model
{
    //The commands for interaction between the server and the client
    public enum Command
    {
        STOP,
        GET_NEXT_FRAME,
        INITIALIZE_SOCKET,
        CREATE_INITIAL_KEYS_EXCHANGE_HANDLER,
        REGISTRATION_HANDLER,
        VERIFICATION_HANDLER,
        VERIFICATION_KEYS_HANDLER,
        SET_PASSWORD,
        SET_USER_NAME,
        SET_EMAIL,
        GET_PASSWORD,
        GET_USER_NAME,
        GET_EMAIL,
        INITIALIZE_INFO_FOR_REGISTRATION,
        RUN_HOST,
        RUN_CONNECTOR,
        START_KEYBOARD_CONTROL,
        START_MOUSE_CONTROL,
        START_TRANSMISSION_HOST,
        START_TRANSMISSION_CONNECTOR,
        STOP_KEYBOARD_CONTROL,
        STOP_MOUSE_CONTROL,
        STOP_TRANSMISSION,
        Null,
        Message,
        ScreenMsg,
        login,
        ERROR,
        IP_REQUEST_HANDLER, //connection request - send
        IP_RESPONSE_PEER_HANDLER, //connection request - listen for requests
        SET_IP, //set ip for srt protocol
        STOP_LISTENING_FOR_REQUESTS,
        SIGN_OUT,
        DELETE_ACCOUNT,
        ALLOW_CONNECTION_REQUEST,
        DENY_CONNECTION_REQUEST,
        logout,
        START_LISTENING
    }



    //The data structure by which the server and the client interact with each other
    //Any data package must have the following structure
    // =============================================================
    // |  Command ID | Name Length | Message Length | Data Message |
    // =============================================================
    public class DataMessage
    {
        public string UserName { get; set; }      //Name by which the client logs into the room
        public String MessageData { get; set; }   //Message text
        public Command DataCommandType { get; set; }  //Command type (login, logout, send message, etcetera)
        public byte[] ScreenArrayData { get; set; }

        //Default constructor
        public DataMessage()
        {
            this.DataCommandType = Command.Null;
            this.MessageData = null;
            this.UserName = null;
            this.ScreenArrayData = null;
        }

        //Converts the bytes into an object of type Data
        public DataMessage(byte[] data)
        {
            //The first four bytes are for the Command
            this.DataCommandType = (Command)BitConverter.ToInt32(data, 0);

            //The next four store the length of the name
            int nameLen = BitConverter.ToInt32(data, 4);

            //The next four store the length of the message
            int msgLen = BitConverter.ToInt32(data, 8);

            //int msgScreenLen = BitConverter.ToInt32(data, 12);

            //This check makes sure that strName has been passed in the array of bytes

            if (nameLen > 0)
                try
                {
                    this.UserName = Encoding.UTF8.GetString(data, 12, nameLen);
                }
                catch (Exception)
                {
                    this.UserName = null;
                }

            else
                this.UserName = null;

            //This checks for a null message field
            if (msgLen > 0)
            {
                try
                {
                    if (this.DataCommandType != null && this.DataCommandType != Command.ScreenMsg) //string message type
                    {
                        this.MessageData = Encoding.UTF8.GetString(data, 12 + nameLen, msgLen);
                    }
                    else if (this.DataCommandType == Command.ScreenMsg)
                    {
                        this.ScreenArrayData = new byte[msgLen];
                        Buffer.BlockCopy(data, 12 + nameLen, this.ScreenArrayData, 0, msgLen);
                    }
                }
                catch (Exception)
                {
                    this.MessageData = null;
                    this.ScreenArrayData = null;
                }

            }
            else
            {
                this.MessageData = null;
                this.ScreenArrayData = null;
            }
        }

        //Converts the Data structure into an array of bytes
        public byte[] ToByte()
        {
            List<byte> result = new List<byte>();

            //First four are for the Command
            result.AddRange(BitConverter.GetBytes((int)DataCommandType));

            //Add the length of the name
            if (UserName != null)
                result.AddRange(BitConverter.GetBytes(UserName.Length));
            else
                result.AddRange(BitConverter.GetBytes(0));

            //Length of the message

            if (DataCommandType == Command.ScreenMsg)
            {
                //Length of the message
                if (ScreenArrayData != null)
                    result.AddRange(BitConverter.GetBytes(ScreenArrayData.Length));
                else
                    result.AddRange(BitConverter.GetBytes(0));
            }
            else if (DataCommandType != null)
            {
                if (MessageData != null)
                    result.AddRange(BitConverter.GetBytes(MessageData.Length));
                else
                    result.AddRange(BitConverter.GetBytes(0));
            }

            //Add the name
            if (UserName != null)
                result.AddRange(Encoding.UTF8.GetBytes(UserName));

            //And, lastly we add the message text to our array of bytes
            if (DataCommandType == Command.ScreenMsg)
            {
                if (ScreenArrayData != null)
                    result.AddRange(ScreenArrayData);
            }

            else if (DataCommandType != null)
            {
                if (MessageData != null)
                    result.AddRange(Encoding.UTF8.GetBytes(MessageData));
            }
            return result.ToArray();
        }

    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace WpfApp1.Model
{
    public delegate void SendMsgUserData(Object sender, String sData);
    public delegate void SendGUIUpdateData(Object sender, String sData);
    public delegate void SendConnectionStatus(Object sender, int iConnectStatus);
    public delegate void SendRecivedScreenData(Object sender, byte[] byteData);
    public delegate void SendRegistrationHandlerResult(Object sender, string sData);
    public delegate void SendLoginHandlerResult(Object sender, string sData);
    public delegate void SendConnectionRequestResult(Object sender, string sData);
    public delegate void SendReceivedConnectionRequest(Object sender, string sData);

    public interface IScreenRemoteModel
    {
        String UserName { get; set; }
        String UserRemoteName { get; set; }
        bool IsConnect { get; set; }

        void Init();
        void DisConnect();
        bool Connect(String sUserName, String sIpAddress, int iPordID);
        bool SendMsgData(String sMessage);
        bool SendCustomMessage(Command command, String sMessage);

        //Events
        event SendMsgUserData msgUserDataEvent;
        event SendGUIUpdateData msgUpdateGUIData;
        event SendConnectionStatus msgConnectionStatus;
        event SendRecivedScreenData msgRecivedScreenData;
        event SendRegistrationHandlerResult msgRegistrationHandlerResult;
        event SendLoginHandlerResult msgLoginHandlerResult;
        event SendConnectionRequestResult msgConnectionRequestResult;
        event SendReceivedConnectionRequest msgReceivedConnectionRequest;
    }
}

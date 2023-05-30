using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace WpfApp1.View
{
    public interface IScreenRemoteView
    {
        int ServerPortID { get; set; }
        string ServerIpAddress { get; set; }
        string UserName { get; set; }
        void UpdateUserDataMsg(string sUserName, string sData);
        void UpdateGUIMessage(string sMessage, bool bEnable, int iWaitMilliSecond = 2000);
        void UpdateConnectionView(int iConnectStatus);
        void UpdateScreenMsgData(byte[] byteScreenData);
        void UpdateRegistrationResult(String result);
        void UpdateLoginResult(String result);
        void UpdateConnectionRequestResult(String result);
        void UpdateClientWithReceivedRequest(string requesting_user_name);
    }
}

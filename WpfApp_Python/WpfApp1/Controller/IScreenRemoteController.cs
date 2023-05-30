using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace WpfApp1.Controller
{
    public interface IScreenRemoteController
    {
        bool ConnectMsg();
        void DisconnectMsg();
        bool SendMsgdata(String sMessage);
        bool SendCustomMessage(Model.Command command, String sMessage);
        bool Init();
    }
}

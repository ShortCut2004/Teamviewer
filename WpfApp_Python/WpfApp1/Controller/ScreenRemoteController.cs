using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using WpfApp1.View;
using WpfApp1.Model;
using System.Diagnostics;

namespace WpfApp1.Controller
{
    public class ScreenRemoteController : IScreenRemoteController
    {
        private IScreenRemoteView _view = null;
        private IScreenRemoteModel _model = null;


        public IScreenRemoteView View
        {
            get
            {
                return _view;
            }
        }

        public ScreenRemoteController(IScreenRemoteView mainWindow)
        {
            _model = new ScreenRemoteModel();
            _view = mainWindow;
            Debug.Assert(_view != null);

            //Events register
            _model.msgUserDataEvent += MsgUserDataEventFunc;
            _model.msgUpdateGUIData += MsgUpdateGUIDataFunc;
            _model.msgConnectionStatus += MsgConnectionStatusFunc;
            _model.msgRecivedScreenData += MsgRecivedScreenDataFunc;
            _model.msgRegistrationHandlerResult += MsgUpdateRegistrationHandlerResult;
            _model.msgLoginHandlerResult += MsgUpdateLoginHandlerResult;
            _model.msgConnectionRequestResult += MsgConnectionRequestResult;
            _model.msgReceivedConnectionRequest += MsgReceivedConnectionRequest;
            //run the python engine
            _model.Init();
        }

        public bool Init()
        {
            if (_model != null)
            {
                _model.Init();
            }

            return true;
        }

        private void MsgRecivedScreenDataFunc(object sender, byte[] byteData)
        {
            _view.UpdateScreenMsgData(byteData);
        }

        private void MsgConnectionStatusFunc(object sender, int iConnectStatus)
        {
            _view.UpdateConnectionView(iConnectStatus);
        }

        private void MsgUpdateGUIDataFunc(object sender, string sData)
        {
            _view.UpdateGUIMessage(sData, true);
        }

        private void MsgUpdateRegistrationHandlerResult(object sender, String sData)
        {
            _view.UpdateRegistrationResult(sData);
        }
        private void MsgUpdateLoginHandlerResult(object sender, String sData)
        {
            _view.UpdateLoginResult(sData);
        }
        private void MsgConnectionRequestResult(object sender, String sData)
        {
            _view.UpdateConnectionRequestResult(sData);
        }
        private void MsgReceivedConnectionRequest(object sender, String sData)
        {
            _view.UpdateClientWithReceivedRequest(sData);
        }
        public bool SendMsgdata(String sMessage)
        {
            return _model.SendMsgData(sMessage);
        }
        public bool SendCustomMessage(Command command, String sMessage)
        {
            return _model.SendCustomMessage(command,sMessage);
        }
        public bool ConnectMsg()
        {
            return _model.Connect(_view.UserName, _view.ServerIpAddress, _view.ServerPortID);
        }

        public void DisconnectMsg()
        {
            _model.DisConnect();
        }
        protected void MsgUserDataEventFunc(object sender, string sData)
        {
            _view.UpdateUserDataMsg(_model.UserRemoteName, sData);
        }
    }
}

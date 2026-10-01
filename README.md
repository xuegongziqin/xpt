# 这是一个进程监视器,Ring 3

启动时, Hollow一个进程cmd/svchost/taskmgr, 把自己inject进去,然后自己作为一个双入口exe,可以被当作dll注入,注入到随机10+进程,从key.ini读取一行一行的进程,检测到就Remove Criticle标记(NtSetInformationProcess), 然后terminate(TerminateProcess)

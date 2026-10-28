package com.ghostlock.app.shizuku;

import com.ghostlock.app.shizuku.IGhostlockCallback;
import com.ghostlock.app.shizuku.IGhostlockStatusCallback;

interface IGhostlockUserService {
    void destroy() = 16777114;
    void runExploit(int primaryCpu, int consumerCpu, boolean safeMode, boolean forceAttack, in byte[] profileBlob, @nullable String debugDir, IGhostlockCallback callback, IGhostlockStatusCallback statusCallback) = 2;
    void runExploitAsManager(int primaryCpu, int consumerCpu, boolean safeMode, boolean forceAttack, in byte[] profileBlob, @nullable String debugDir, @nullable String managerPackage, IGhostlockCallback callback, IGhostlockStatusCallback statusCallback) = 3;
    void runCve64560(in byte[] fanout, in byte[] rotate, in byte[] su, @nullable String debugDir, IGhostlockCallback callback, IGhostlockStatusCallback statusCallback) = 4;
    void runCve98260(in byte[] payload, in byte[] su, @nullable String debugDir, IGhostlockCallback callback, IGhostlockStatusCallback statusCallback) = 5;
}

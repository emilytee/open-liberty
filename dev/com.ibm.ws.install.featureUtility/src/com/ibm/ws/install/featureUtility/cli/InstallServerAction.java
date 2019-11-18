package com.ibm.ws.install.featureUtility.cli;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ibm.ws.install.InstallException;
import com.ibm.ws.install.InstallKernelFactory;
import com.ibm.ws.install.InstallKernelInteractive;
import com.ibm.ws.install.featureUtility.FeatureUtility;
import com.ibm.ws.install.featureUtility.FeatureUtilityExecutor;
import com.ibm.ws.install.internal.InstallLogUtils;
import com.ibm.ws.install.internal.InstallUtils;
import com.ibm.ws.install.internal.ProgressBar;
import com.ibm.ws.install.internal.asset.ServerAsset;
import com.ibm.ws.kernel.boot.ReturnCode;
import com.ibm.ws.kernel.boot.cmdline.ActionHandler;
import com.ibm.ws.kernel.boot.cmdline.Arguments;
import com.ibm.ws.kernel.boot.cmdline.ExitCode;
import com.ibm.ws.kernel.provisioning.BundleRepositoryRegistry;
import com.ibm.ws.product.utility.CommandConsole;
import com.ibm.ws.product.utility.CommandTaskRegistry;
import com.ibm.ws.product.utility.ExecutionContext;
import com.ibm.ws.product.utility.extension.ValidateCommandTask;

public class InstallServerAction implements ActionHandler {

        private FeatureUtility featureUtility;
        private InstallKernelInteractive installKernel;
        private Set<ServerAsset> servers;
        private Logger logger;
        private List<String> argList;
        private List<String> featureNames;
        private String fromDir;
        private String toDir;
        private ProgressBar progressBar;


        @Override public ExitCode handleTask(PrintStream stdout, PrintStream stderr, Arguments args) {
                ExitCode rc = initialize(args);
                if (!!!rc.equals(ReturnCode.OK)) {
                        return rc;
                }
                rc = execute();
                
                return rc;

        }


        private ExitCode initialize(Arguments args){
                ExitCode rc = ReturnCode.OK;

                this.logger = InstallLogUtils.getInstallLogger();
                this.installKernel = InstallKernelFactory.getInteractiveInstance();
                this.featureNames = new ArrayList<String>();
                this.servers = new HashSet<>();

                this.argList = args.getPositionalArguments();
                this.fromDir = args.getOption("from");
                if ((rc = validateFromDir(this.fromDir)) != ReturnCode.OK) {
                        return rc;
                }


                this.toDir = args.getOption("to");

                this.progressBar = ProgressBar.getInstance();

                HashMap<String, Integer> methodMap = new HashMap<>();
                // initialize feature utility and install kernel map
                methodMap.put("initializeMap", 10);
                methodMap.put("fetchJsons", 10);
                // in installFeature we have 80 units to work with
                methodMap.put("resolvedFeatures", 20);
                methodMap.put("fetchArtifacts", 20);
                methodMap.put("installFeatures", 30);
                methodMap.put("cleanUp", 10);

                progressBar.setMethodMap(methodMap);

                String arg = argList.get(0);
                try {
                        if (isServer(arg)) {
                                return serverInit(arg);
                        } else {
                               throw new InstallException(InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getMessage("ERROR_SERVER_NOT_EXIST", arg));
                        }
                } catch (InstallException e) {
                        logger.log(Level.SEVERE, e.getMessage(), e);
                        return FeatureUtilityExecutor.returnCode(e.getRc());
                } catch (Throwable e) {
                        logger.log(Level.SEVERE, e.getMessage(), e);
                        return FeatureUtilityExecutor.returnCode(InstallException.IO_FAILURE);
                }

        }
        private ReturnCode serverInit(String fileName) throws InstallException, IOException {

                File serverXML = (fileName.toLowerCase().endsWith(InstallUtils.SERVER_XML)) ? new File(fileName)
                                : new File(InstallUtils.getServersDir(), fileName + File.separator + InstallUtils.SERVER_XML);

                if (!serverXML.isFile()) {
                        throw new InstallException(InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("ERROR_UNABLE_TO_FIND_SERVER_XML",
                                                                                                                  serverXML.getParent()));
                        // throw new InstallException("Unable to find server.xml file",
                        // InstallException.RUNTIME_EXCEPTION);
                }

                servers.add(new ServerAsset(serverXML));

                return ReturnCode.OK;
        }


        private static boolean isServer(String fileName) {
                return new File(InstallUtils.getServersDir(), fileName).isDirectory()
                       || fileName.toLowerCase().endsWith("server.xml");
        }

        private ReturnCode validateFromDir(String fromDir) {
                if (fromDir == null) {
                        return ReturnCode.OK;
                }
                if (fromDir.isEmpty()) {
                        logger.log(Level.SEVERE,
                                   InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("ERROR_TOOL_DIRECTORY_REQUIRED", "from"));
                        return ReturnCode.BAD_ARGUMENT;
                }

                if (!new File(fromDir).exists()) {
                        logger.log(Level.SEVERE,
                                   InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("ERROR_TOOL_DIRECTORY_NOT_EXISTS", fromDir));
                        return ReturnCode.BAD_ARGUMENT;
                }

                return ReturnCode.OK;
        }
        private ExitCode installServerFeatures() {
                ExitCode rc = ReturnCode.OK;
                Collection<String> featuresToInstall = new HashSet<String>();

                try {
                        featuresToInstall.addAll(installKernel.getServerFeaturesToInstall(servers, false));
                } catch (InstallException ie) {
                        logger.log(Level.SEVERE, ie.getMessage(), ie);
                        return FeatureUtilityExecutor.returnCode(ie.getRc());
                } catch (Exception e) {
                        logger.log(Level.SEVERE, e.getMessage(), e);
                        rc = ReturnCode.RUNTIME_EXCEPTION;
                }

                if (featuresToInstall.isEmpty()) {
                        logger.log(Level.FINE, "Additional server features are not required.");
                } else {
                        logger.log(Level.FINE, "Additional server features required.");
                        rc = assetInstallInit(featuresToInstall);
                }

                return rc;
        }


        private ExitCode assetInstallInit(Collection<String> assetIds) {
                featureNames.addAll(assetIds);
                return ReturnCode.OK;
        }

        private ExitCode install() {
                try {
                        featureUtility = new FeatureUtility.FeatureUtilityBuilder().setFromDir(fromDir).setToExtension(toDir)
                                        .setFeaturesToInstall(featureNames).build();
                        featureUtility.installFeatures();
                } catch (InstallException e) {
                        logger.log(Level.SEVERE, e.getMessage(), e);
                        return FeatureUtilityExecutor.returnCode(e.getRc());
                } catch (Throwable e) {
                        logger.log(Level.SEVERE, e.getMessage(), e);
                        return FeatureUtilityExecutor.returnCode(InstallException.IO_FAILURE);
                }
                return ReturnCode.OK;
        }



        private ExitCode execute() {
                ExitCode rc = ReturnCode.OK;

                // check any newly deployed servers for missing required features
                if (!servers.isEmpty()) {
                        rc = installServerFeatures();
                }
                if (ReturnCode.OK.equals(rc) && !featureNames.isEmpty()) {
                        rc = install();
                }
                if(ReturnCode.OK.equals(rc)){
                        progressBar.finish();
                } else {
                        progressBar.finishWithError();
                }

                if (ReturnCode.OK.equals(rc)) {
                        if (!!!validateProduct()) {
                                rc = ReturnCode.INVALID;
                        }
                }


                return rc;

        }

        private boolean validateProduct() {
                logger.log(Level.INFO, "");
                BundleRepositoryRegistry.disposeAll();
                BundleRepositoryRegistry.initializeDefaults(null, false);
                ValidateCommandTask vcTask = new ValidateCommandTask();
                vcTask.setPrintErrorOnly(true);
                vcTask.setPrintStartMessage(true);
                vcTask.doExecute(new ExecutionContext() {

                        @Override
                        public CommandConsole getCommandConsole() {
                                return new CommandConsole() {

                                        @Override
                                        public boolean isInputStreamAvailable() {
                                                return false;
                                        }

                                        @Override
                                        public String readMaskedText(String prompt) {
                                                return null;
                                        }

                                        @Override
                                        public String readText(String prompt) {
                                                return null;
                                        }

                                        @Override
                                        public void printInfoMessage(String message) {
                                                logger.log(Level.INFO, message);
                                        }

                                        @Override
                                        public void printlnInfoMessage(String message) {
                                                logger.log(Level.INFO, message);
                                        }

                                        @Override
                                        public void printErrorMessage(String errorMessage) {
                                                logger.log(Level.SEVERE, errorMessage);
                                        }

                                        @Override
                                        public void printlnErrorMessage(String errorMessage) {
                                                logger.log(Level.SEVERE, errorMessage);
                                        }
                                };
                        }

                        @Override
                        public String[] getArguments() {
                                return null;
                        }

                        @Override
                        public Set<String> getOptionNames() {
                                return new HashSet<String>();
                        }

                        @Override
                        public String getOptionValue(String option) {
                                return null;
                        }

                        @Override
                        public boolean optionExists(String option) {
                                return false;
                        }

                        @Override
                        public CommandTaskRegistry getCommandTaskRegistry() {
                                return null;
                        }

                        @Override
                        public <T> T getAttribute(String name, Class<T> cls) {
                                return null;
                        }

                        @Override
                        public Object getAttribute(String name) {
                                return null;
                        }

                        @Override
                        public void setAttribute(String name, Object value) {
                        }

                        @Override
                        public void setOverrideOutputStream(PrintStream outputStream) {
                        }
                });
                return vcTask.isSuccessful();
        }
}

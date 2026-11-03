"""Cyberbot authentication is following DAC access control, where each member that have admin account with Cyberbot MUST BE granted by the Server Owner to alter the configuration of Cyberbot for the server"""
from __future__ import annotations

from CyberBotArchiveDiskImageScanModule import *
from CyberBotURLPreprocessingModule import *
from CyberBotEncoderTransformersModule import loadClassifierModel, Prediction
from CyberBotAnalyticsModule import *
from CyberBotScheduledTasksModule import *
from CyberBotSecurityUtilitiesModule import *
from CyberBotLLMScanModule import *
from CyberBotHashDatabaseModule import *
from CyberBotFileUtilitiesModule import *
from CyberBotVirusTotalModule import *
from CyberBotGhidraIntegrationModule import *
from CyberBotAdminCommandsModule import *
from CyberBotOtherCommandsModule import *
from CyberBotAttachmentScanModule import *
from CyberBotURLScanModule import *
from CyberBotScanOrchestrationModule import *
from CyberBotEventHandlersModule import *

# CHANGED: Only start the Discord bot when launching this entry point.
if __name__ == "__main__":
    Cyberbot.run(DISCORD_BOT_TOKEN)

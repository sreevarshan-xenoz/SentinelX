# SentinelX API Server

import logging
import os
import sys
import json
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
import uuid

# Import FastAPI
try:
    from fastapi import FastAPI, HTTPException, Depends, Query, Path, Body, status, BackgroundTasks
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from fastapi.security import APIKeyHeader
    from pydantic import BaseModel, Field
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ..core.config_manager import ConfigManager
from ..core.logging_manager import LoggingManager
from ..model_layer.model_factory import ModelFactory
from ..threat_enrichment.threat_enricher import ThreatEnricher
from ..threat_enrichment.alert_manager import AlertManager, Alert
from ..network.packet_capture import PacketCapture
from ..network.flow_analyzer import FlowAnalyzer


# Define Pydantic models for request/response validation
class PredictionRequest(BaseModel):
    """Model for prediction requests."""
    features: Dict[str, Any] = Field(..., description="Features for prediction")


class EnrichmentRequest(BaseModel):
    """Model for enrichment requests."""
    target: str = Field(..., description="IP address or domain to enrich")
    type: str = Field("ip", description="Type of target (ip or domain)")


class AlertResponse(BaseModel):
    """Model for alert responses."""
    alert_id: str
    alert_type: str
    severity: str
    source: str
    timestamp: str
    details: Dict[str, Any]
    enrichment: Optional[Dict[str, Any]] = None
    status: str
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None
    resolution_timestamp: Optional[str] = None


class AlertUpdateRequest(BaseModel):
    """Model for alert update requests."""
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None


class CaptureRequest(BaseModel):
    """Model for packet capture requests."""
    interface: Optional[str] = None
    duration: int = Field(60, description="Capture duration in seconds")
    filter: Optional[str] = None
    max_packets: Optional[int] = None


class APIServer:
    """API server for SentinelX.
    
    This class provides a RESTful API for interacting with the SentinelX system.
    """
    
    def __init__(self):
        """Initialize the API server."""
        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI is not available. Please install it: pip install fastapi uvicorn")
        
        self.config = ConfigManager()
        self.logger = logging.getLogger(__name__)
        
        # Get API configuration
        self.api_config = self.config.get('api', {})
        self.host = self.api_config.get('host', '127.0.0.1')
        self.port = self.api_config.get('port', 8000)
        self.api_key = self.api_config.get('api_key', str(uuid.uuid4()))
        self.enable_cors = self.api_config.get('enable_cors', True)
        self.cors_origins = self.api_config.get('cors_origins', ["*"])
        
        # Initialize components
        self.model_factory = ModelFactory()
        self.threat_enricher = ThreatEnricher()
        self.alert_manager = AlertManager()
        self.packet_capture = PacketCapture()
        self.flow_analyzer = FlowAnalyzer()
        
        # Create FastAPI app
        self.app = FastAPI(
            title="SentinelX API",
            description="API for SentinelX Cyber Threat Intelligence System",
            version="1.0.0"
        )
        
        # Add CORS middleware if enabled
        if self.enable_cors:
            self.app.add_middleware(
                CORSMiddleware,
                allow_origins=self.cors_origins,
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
        
        # Set up API key security
        self.api_key_header = APIKeyHeader(name="X-API-Key")
        
        # Register routes
        self._register_routes()
        
        self.logger.info("API server initialized")
    
    def _register_routes(self):
        """Register API routes."""
        # API key dependency
        async def get_api_key(api_key: str = Depends(self.api_key_header)):
            if api_key != self.api_key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid API Key",
                )
            return api_key
        
        # Root endpoint
        @self.app.get("/")
        async def root():
            return {"message": "Welcome to SentinelX API"}
        
        # Health check endpoint
        @self.app.get("/health")
        async def health_check():
            return {"status": "ok", "timestamp": datetime.now().isoformat()}
        
        # Prediction endpoint
        @self.app.post("/predict", dependencies=[Depends(get_api_key)])
        async def predict(request: PredictionRequest):
            try:
                # Get default model
                model = self.model_factory.get_model()
                
                # Make prediction
                prediction = model.predict([request.features])[0]
                probability = model.predict_proba([request.features])[0]
                
                # Create response
                response = {
                    "prediction": prediction,
                    "probability": probability.tolist() if hasattr(probability, "tolist") else probability,
                    "timestamp": datetime.now().isoformat()
                }
                
                return response
            
            except Exception as e:
                self.logger.error(f"Error in prediction: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Prediction error: {str(e)}"
                )
        
        # Enrichment endpoint
        @self.app.post("/enrich", dependencies=[Depends(get_api_key)])
        async def enrich(request: EnrichmentRequest):
            try:
                # Perform enrichment
                if request.type.lower() == "ip":
                    result = self.threat_enricher.enrich_ip(request.target)
                elif request.type.lower() == "domain":
                    result = self.threat_enricher.enrich_domain(request.target)
                else:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid target type. Must be 'ip' or 'domain'."
                    )
                
                # Create response
                response = {
                    "target": request.target,
                    "type": request.type,
                    "result": result,
                    "timestamp": datetime.now().isoformat()
                }
                
                return response
            
            except Exception as e:
                self.logger.error(f"Error in enrichment: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Enrichment error: {str(e)}"
                )
        
        # Alerts endpoints
        @self.app.get("/alerts", dependencies=[Depends(get_api_key)])
        async def get_alerts(
            limit: int = Query(10, description="Maximum number of alerts to return"),
            severity: Optional[str] = Query(None, description="Filter by severity"),
            status: Optional[str] = Query(None, description="Filter by status"),
            alert_type: Optional[str] = Query(None, description="Filter by alert type")
        ):
            try:
                # Build filters
                filters = {}
                if severity:
                    filters["severity"] = severity
                if status:
                    filters["status"] = status
                if alert_type:
                    filters["alert_type"] = alert_type
                
                # Get alerts
                alerts = self.alert_manager.get_alerts(filters=filters, limit=limit)
                
                # Convert to response model
                response = [AlertResponse(**alert.to_dict()) for alert in alerts]
                
                return response
            
            except Exception as e:
                self.logger.error(f"Error getting alerts: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error getting alerts: {str(e)}"
                )
        
        @self.app.get("/alerts/{alert_id}", dependencies=[Depends(get_api_key)])
        async def get_alert(alert_id: str = Path(..., description="Alert ID")):
            try:
                # Get alert
                alert = self.alert_manager.get_alert(alert_id)
                
                if not alert:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"Alert not found: {alert_id}"
                    )
                
                # Convert to response model
                response = AlertResponse(**alert.to_dict())
                
                return response
            
            except HTTPException:
                raise
            
            except Exception as e:
                self.logger.error(f"Error getting alert: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error getting alert: {str(e)}"
                )
        
        @self.app.put("/alerts/{alert_id}", dependencies=[Depends(get_api_key)])
        async def update_alert(
            alert_id: str = Path(..., description="Alert ID"),
            request: AlertUpdateRequest = Body(...)
        ):
            try:
                # Build update kwargs
                kwargs = {}
                if request.status is not None:
                    kwargs["status"] = request.status
                if request.assigned_to is not None:
                    kwargs["assigned_to"] = request.assigned_to
                if request.resolution_notes is not None:
                    kwargs["resolution_notes"] = request.resolution_notes
                    if request.status is None and kwargs["resolution_notes"]:
                        kwargs["status"] = "resolved"
                
                # Update alert
                alert = self.alert_manager.update_alert(alert_id, **kwargs)
                
                if not alert:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"Alert not found: {alert_id}"
                    )
                
                # Convert to response model
                response = AlertResponse(**alert.to_dict())
                
                return response
            
            except HTTPException:
                raise
            
            except Exception as e:
                self.logger.error(f"Error updating alert: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error updating alert: {str(e)}"
                )
        
        # Network monitoring endpoints
        @self.app.post("/capture", dependencies=[Depends(get_api_key)])
        async def start_capture(
            request: CaptureRequest,
            background_tasks: BackgroundTasks
        ):
            try:
                # Get available interfaces
                interfaces = self.packet_capture.get_available_interfaces()
                
                # Use specified interface or first available
                interface = request.interface
                if not interface and interfaces:
                    interface = interfaces[0]
                
                if not interface:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="No network interface specified or available"
                    )
                
                # Generate output file
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_file = os.path.join(
                    self.packet_capture.pcap_dir,
                    f"api_capture_{timestamp}.pcap"
                )
                
                # Start capture in background
                def do_capture():
                    self.packet_capture.capture_to_file(
                        output_file=output_file,
                        duration=request.duration,
                        interface=interface,
                        capture_filter=request.filter
                    )
                
                background_tasks.add_task(do_capture)
                
                # Create response
                response = {
                    "status": "started",
                    "interface": interface,
                    "duration": request.duration,
                    "filter": request.filter,
                    "output_file": output_file,
                    "timestamp": datetime.now().isoformat()
                }
                
                return response
            
            except Exception as e:
                self.logger.error(f"Error starting capture: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error starting capture: {str(e)}"
                )
        
        @self.app.get("/interfaces", dependencies=[Depends(get_api_key)])
        async def get_interfaces():
            try:
                # Get available interfaces
                interfaces = self.packet_capture.get_available_interfaces()
                
                # Create response
                response = {
                    "interfaces": interfaces,
                    "timestamp": datetime.now().isoformat()
                }
                
                return response
            
            except Exception as e:
                self.logger.error(f"Error getting interfaces: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error getting interfaces: {str(e)}"
                )
        
        @self.app.get("/flows", dependencies=[Depends(get_api_key)])
        async def get_flows(
            limit: int = Query(10, description="Maximum number of flows to return")
        ):
            try:
                # Get active flows
                flows = self.flow_analyzer.get_active_flows(limit=limit)
                
                # Create response
                response = {
                    "flows": flows,
                    "timestamp": datetime.now().isoformat()
                }
                
                return response
            
            except Exception as e:
                self.logger.error(f"Error getting flows: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error getting flows: {str(e)}"
                )
        
        @self.app.get("/top-talkers", dependencies=[Depends(get_api_key)])
        async def get_top_talkers(
            limit: int = Query(10, description="Maximum number of talkers to return")
        ):
            try:
                # Get top talkers
                top_talkers = self.flow_analyzer.get_top_talkers(limit=limit)
                
                # Create response
                response = {
                    "top_talkers": top_talkers,
                    "timestamp": datetime.now().isoformat()
                }
                
                return response
            
            except Exception as e:
                self.logger.error(f"Error getting top talkers: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error getting top talkers: {str(e)}"
                )
        
        # System information endpoints
        @self.app.get("/system/info", dependencies=[Depends(get_api_key)])
        async def get_system_info():
            try:
                # Get model information
                models = self.model_factory.list_available_models()
                default_model = self.model_factory.get_default_model_name()
                
                # Get flow statistics
                flow_stats = self.flow_analyzer.get_flow_statistics()
                
                # Get alert statistics
                alerts = self.alert_manager.get_alerts()
                alert_stats = {
                    "total": len(alerts),
                    "by_severity": {},
                    "by_status": {}
                }
                
                # Count alerts by severity and status
                for alert in alerts:
                    # By severity
                    if alert.severity not in alert_stats["by_severity"]:
                        alert_stats["by_severity"][alert.severity] = 0
                    alert_stats["by_severity"][alert.severity] += 1
                    
                    # By status
                    if alert.status not in alert_stats["by_status"]:
                        alert_stats["by_status"][alert.status] = 0
                    alert_stats["by_status"][alert.status] += 1
                
                # Create response
                response = {
                    "system": {
                        "version": "1.0.0",
                        "uptime": "N/A"  # TODO: Track uptime
                    },
                    "models": {
                        "available": models,
                        "default": default_model
                    },
                    "network": flow_stats,
                    "alerts": alert_stats,
                    "timestamp": datetime.now().isoformat()
                }
                
                return response
            
            except Exception as e:
                self.logger.error(f"Error getting system info: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error getting system info: {str(e)}"
                )
    
    def start(self, host: Optional[str] = None, port: Optional[int] = None):
        """Start the API server.
        
        Args:
            host: Host to bind to (overrides config)
            port: Port to bind to (overrides config)
        """
        # Override config with provided parameters
        host = host or self.host
        port = port or self.port
        
        self.logger.info(f"Starting API server on {host}:{port}")
        self.logger.info(f"API Key: {self.api_key}")
        
        # Start server
        uvicorn.run(self.app, host=host, port=port)


def main():
    """Main entry point for the API server."""
    try:
        # Initialize logging
        LoggingManager()
        
        # Create and start API server
        api_server = APIServer()
        api_server.start()
    
    except Exception as e:
        logging.error(f"Error starting API server: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
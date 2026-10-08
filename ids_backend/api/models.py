from django.db import models


class RegisteredSite(models.Model):
    name = models.CharField(max_length=200)
    domain = models.CharField(max_length=200)
    ip_address = models.GenericIPAddressField()
    registered_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class RegisteredDevice(models.Model):
    DEVICE_TYPES = [
        ('camera', 'IP Camera'),
        ('laptop', 'Laptop'),
        ('phone', 'Mobile Phone'),
        ('router', 'Router'),
        ('doorbell', 'IP Doorbell'),
        ('other', 'Other'),
    ]
    name = models.CharField(max_length=200)
    ip_address = models.GenericIPAddressField()
    device_type = models.CharField(max_length=50, choices=DEVICE_TYPES)
    registered_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    last_seen = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.name


class FlowRecord(models.Model):
    SOURCE_TYPES = [('website', 'Website'), ('home_network', 'Home Network')]

    timestamp = models.DateTimeField()
    src_ip = models.GenericIPAddressField(null=True, blank=True)
    dst_ip = models.GenericIPAddressField(null=True, blank=True)
    dst_port = models.IntegerField(default=0)
    protocol = models.IntegerField(default=0)
    prediction = models.CharField(max_length=100)
    confidence = models.FloatField()
    is_alert = models.BooleanField(default=False)
    severity = models.CharField(max_length=20, default='NORMAL')
    flow_duration = models.FloatField(default=0)
    flow_bytes_per_sec = models.FloatField(default=0)
    flow_packets_per_sec = models.FloatField(default=0)
    total_fwd_packets = models.IntegerField(default=0)
    total_bwd_packets = models.IntegerField(default=0)
    source_type = models.CharField(max_length=20, choices=SOURCE_TYPES, default='website')
    registered_id = models.CharField(max_length=50, null=True, blank=True)
    recommended_action = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['src_ip']),
            models.Index(fields=['prediction']),
            models.Index(fields=['is_alert']),
            models.Index(fields=['source_type']),
            models.Index(fields=['severity']),
        ]
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.prediction} - {self.src_ip} at {self.timestamp}"


class Incident(models.Model):
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('acknowledged', 'Acknowledged'),
        ('resolved', 'Resolved'),
    ]
    flow = models.ForeignKey(FlowRecord, on_delete=models.CASCADE, related_name='incidents')
    attack_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=20)
    src_ip = models.GenericIPAddressField(null=True, blank=True)
    dst_ip = models.GenericIPAddressField(null=True, blank=True)
    recommended_action = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.attack_type} - {self.status}"


class SystemHealth(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    kafka_status = models.BooleanField(default=False)
    ml_consumer_status = models.BooleanField(default=False)
    cicflowmeter_status = models.BooleanField(default=False)
    tcpdump_status = models.BooleanField(default=False)
    flows_per_minute = models.IntegerField(default=0)
    alerts_per_minute = models.IntegerField(default=0)
    kafka_queue_size = models.IntegerField(default=0)
    flows_processed_total = models.IntegerField(default=0)
    alerts_triggered_total = models.IntegerField(default=0)
    uptime_since = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"Health at {self.timestamp}"


class TargetHealth(models.Model):
    TARGET_TYPES = [('website', 'Website'), ('device', 'Device')]
    timestamp = models.DateTimeField(auto_now_add=True)
    target_type = models.CharField(max_length=20, choices=TARGET_TYPES)
    site = models.ForeignKey(RegisteredSite, null=True, blank=True, on_delete=models.SET_NULL)
    device = models.ForeignKey(RegisteredDevice, null=True, blank=True, on_delete=models.SET_NULL)
    is_reachable = models.BooleanField(default=False)
    response_time_ms = models.FloatField(null=True, blank=True)
    status_code = models.IntegerField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']


class SimulationSession(models.Model):
    ATTACK_TYPES = [
        ('portscan', 'Port Scan'),
        ('sqli', 'SQL Injection'),
        ('bruteforce', 'Brute Force'),
        ('dos', 'DoS'),
        ('xss', 'XSS'),
    ]
    STATUS_CHOICES = [
        ('running', 'Running'),
        ('stopped', 'Stopped'),
        ('completed', 'Completed'),
    ]
    attack_type = models.CharField(max_length=50, choices=ATTACK_TYPES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='running')
    # Which detection lane this run belongs to: 'website' (CNN) or 'iot_test' (TON-IoT)
    source_type = models.CharField(max_length=30, default='website')
    started_at = models.DateTimeField(auto_now_add=True)
    stopped_at = models.DateTimeField(null=True, blank=True)
    flows_generated = models.IntegerField(default=0)
    alerts_triggered = models.IntegerField(default=0)

    class Meta:
        ordering = ['-started_at']


class BlockedIP(models.Model):
    ip = models.GenericIPAddressField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip


class WhitelistedIP(models.Model):
    ip = models.GenericIPAddressField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip


class SiemConfig(models.Model):
    es_url = models.CharField(max_length=255, default='http://localhost:9200')
    index_name = models.CharField(max_length=100, default='nexa-flows')
    is_connected = models.BooleanField(default=False)
    last_synced = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.es_url}/{self.index_name} (Connected: {self.is_connected})"


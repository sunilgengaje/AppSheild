import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'AppShield Flutter Sample',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blue),
        useMaterial3: true,
      ),
      home: const AppShieldDashboard(),
    );
  }
}

class AppShieldDashboard extends StatefulWidget {
  const AppShieldDashboard({super.key});

  @override
  State<AppShieldDashboard> createState() => _AppShieldDashboardState();
}

class _AppShieldDashboardState extends State<AppShieldDashboard> {
  static const platform = MethodChannel('com.appshield/security');
  
  String _securityStatus = 'Unknown';
  int _riskScore = 0;
  bool _isPoisoned = false;

  Future<void> _checkSecurity() async {
    try {
      final Map<dynamic, dynamic> result = await platform.invokeMethod('checkSecurity');
      setState(() {
        _riskScore = result['riskScore'];
        _isPoisoned = result['isPoisoned'];
        _securityStatus = _isPoisoned ? "🚨 COMPROMISED" : "🛡️ SECURE";
      });
    } on PlatformException catch (e) {
      setState(() {
        _securityStatus = "Failed to get security status: '\${e.message}'.";
      });
    }
  }

  @override
  void initState() {
    super.initState();
    _checkSecurity(); // Check on launch
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('AppShield Security Center'),
        backgroundColor: Colors.blueGrey,
        foregroundColor: Colors.white,
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.shield_outlined, size: 80, color: Colors.blueGrey),
            const SizedBox(height: 20),
            Text(
              'Environment Status:',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            Text(
              _securityStatus,
              style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                color: _isPoisoned ? Colors.red : Colors.green,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 30),
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.grey[200],
                borderRadius: BorderRadius.circular(10),
              ),
              child: Column(
                children: [
                  Text('Aggregate Risk Score: \$_riskScore / 100'),
                  const SizedBox(height: 10),
                  LinearProgressIndicator(
                    value: _riskScore / 100,
                    backgroundColor: Colors.white,
                    color: _riskScore > 50 ? Colors.red : Colors.orange,
                  ),
                ],
              ),
            ),
            const SizedBox(height: 40),
            ElevatedButton.icon(
              onPressed: _checkSecurity,
              icon: const Icon(Icons.refresh),
              label: const Text('Refresh Security Sweep'),
              style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

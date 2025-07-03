document.addEventListener('DOMContentLoaded', function() {
    const startAttendanceButton = document.getElementById('startAttendance');
    const video = document.getElementById('video');
    const canvas = document.getElementById('canvas');
    const status = document.getElementById('status');
    const context = canvas.getContext('2d');
    let stream = null;

    // Check webcam permission status
    async function checkWebcamPermission() {
        try {
            const permissionStatus = await navigator.permissions.query({ name: 'camera' });
            if (permissionStatus.state === 'denied') {
                status.textContent = 'Camera access denied. Please allow camera access in your browser settings.';
                status.className = 'text-danger';
                return false;
            }
            return true;
        } catch (err) {
            console.error('Error checking webcam permission:', err);
            status.textContent = 'Error checking camera permission: ' + err.message;
            status.className = 'text-danger';
            return false;
        }
    }

    // Start webcam feed
    async function startWebcam() {
        try {
            stream = await navigator.mediaDevices.getUserMedia({ video: true });
            video.srcObject = stream;
            console.log('Webcam started successfully');
            return true;
        } catch (err) {
            console.error('Error accessing webcam:', err);
            status.textContent = 'Error accessing webcam: ' + err.message;
            status.className = 'text-danger';
            return false;
        }
    }

    // Stop webcam feed
    function stopWebcam() {
        if (stream) {
            stream.getTracks().forEach(track => track.stop());
            video.srcObject = null;
            stream = null;
            console.log('Webcam stopped');
        }
    }

    startAttendanceButton.addEventListener('click', async function() {
        if (stream) {
            stopWebcam();
            startAttendanceButton.textContent = 'Start Attendance';
            status.textContent = '';
            return;
        }

        const hasPermission = await checkWebcamPermission();
        if (!hasPermission) return;

        const started = await startWebcam();
        if (started) {
            startAttendanceButton.textContent = 'Stop Attendance';
            recognizeFaces();
        }
    });

    function recognizeFaces() {
        if (!stream) {
            console.log('Recognition stopped: Webcam is off');
            return;
        }

        try {
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            context.drawImage(video, 0, 0, canvas.width, canvas.height);
            const imageData = canvas.toDataURL('image/jpeg');
            console.log('Captured image data:', imageData.substring(0, 50) + '...');

            const formData = new FormData();
            formData.append('image', imageData);

            fetch('/recognize', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                console.log('Fetch response status:', response.status);
                return response.json();
            })
            .then(data => {
                console.log('Recognition response:', data);
                if (data.error) {
                    status.textContent = data.error;
                    status.className = 'text-danger';
                } else {
                    status.textContent = `${data.name} (${data.login_id}) - ${data.status}`;
                    status.className = 'text-success';
                }
            })
            .catch(err => {
                console.error('Fetch error:', err);
                status.textContent = 'Recognition error: ' + err.message;
                status.className = 'text-danger';
            });
        } catch (err) {
            console.error('Error capturing image:', err);
            status.textContent = 'Error capturing image: ' + err.message;
            status.className = 'text-danger';
        }

        if (stream) {
            setTimeout(recognizeFaces, 2000);
        }
    }
});
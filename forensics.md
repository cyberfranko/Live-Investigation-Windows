#### Linux Forensics
Performing digital forensics on an ext2 filesystem image requires a methodical, read-only approach to preserve evidence integrity. Ext2 is a non-journaled filesystem, so it lacks recovery logs, but this alss means deleted files (marked in inodes) can often be recovered if thespace hasn't been overwritten. 
```
dd if=original.img of=copy.img bs=4M status=progress
```
Key Principles
- Chain of custody: Document every step
- Read-only access: Use loop devices or forensic tools to prevent writes.
- Hash verification: Computer MD5/SHA256 hashes of the image before/after analysis to detect tampering.

Always work on a copy of the image to avoid altering the original
```
dd if=original.img of=copy.img bs=4M satus=progress
```

##### Step 1: Initial Verification and Setup
- Hash the image for integrity:
```
md5sum evidence.img > hash_md5.txt
sha256sum evidence.img > hash_sha256.txt
```

#### Identify filesystem details
Use fsstat from TSK:
```
sudo apt install sleuthkit # If not installed
fsstat evidence.img
```
This shows block size, inode count, superblock info, etc. Look for ext2 markers

##### Step 2: Mount the image Read-Only for Basic Browsing
- Create a loop device and mount:
```
sudo losetup -r -P /dev/loop0 evidence.img # -r for read-only, -P for partitions
sudo mkdir /mnt/forensic
sudo mount -t ext2 -o ro,noload /dev/loop0p1 /mnt/forensic # Adjust 'p1' for partition
```
- Browse with ls -la /mnt/forensic or find /mnt/forensic -name "*.txt"
- Unmount safely: sudo umount /mnt/forensic && sudo losetup -d /dev/loop0




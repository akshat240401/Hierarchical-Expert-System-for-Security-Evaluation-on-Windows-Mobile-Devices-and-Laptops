import subprocess

# # Get a list of installed drivers
# driver_list = subprocess.check_output('driverquery', shell=True)

# # Parse the output to extract driver information
# driver_info = driver_list.decode('utf-8').split('\n')[1:]
# driver_info = [d.split() for d in driver_info if len(d) > 0]
# print(driver_info)

# # Check each driver for digital signature
# for driver in driver_info:
#     name = driver[0]
#     path = driver[-1]
#     try:
#         output = subprocess.check_output(['sigcheck64.exe', '-i', path], stderr=subprocess.STDOUT, shell=True)
#         print(output)
#         signature = output.decode('utf-8').split('\n')[1]
#         if "Signed" not in signature:
#             print(f"{name} is not digitally signed.")
#         else:
#             print(f"{name} is digitally signed and trusted.")
#     except subprocess.CalledProcessError as e:
#         print(f"Error checking signature for {name}: {e.output}")



def get_driver_signatures():

    # try:
    #     path = "C:\\Windows\\system32\\drivers\\SpatialGraphFilter.sys"
    #     output = subprocess.check_output(['sigcheck64.exe', '-i', path], stderr=subprocess.STDOUT, shell=True)
    #     # print(output)
    #     signature = output.decode('utf-8').split('\n')[1]
    #     if "Signed" not in signature:
    #         print(f"wtd is not digitally signed.")
    #         # signed_drivers.append(name)
    #     else:
    #         print(f"wtd is digitally signed and trusted.")
    #         # signed_drivers.append(name)
    # except subprocess.CalledProcessError as e:
    #     # print(e.output)
    #     if "Signed" not in (f"{e.output}"):
    #         print("not signed")
    #     else:
    #         print("signed")
        # pass
    result = subprocess.run(['driverquery', '/v'], stdout=subprocess.PIPE)
    drivers = result.stdout.decode().split('\n')
    d = []
    for k in drivers:
        n = k.split()
        if len(n) > 0:
            d.append([n[0],n[-2]])
    d = d[2:]
    signed_drivers = []
    unsigned_drivers = []
    for driver in d:
        name = driver[0]
        path = driver[-1]
        try:
            output = subprocess.check_output(['sigcheck64.exe', '-i', path], stderr=subprocess.STDOUT, shell=True)
            signature = output.decode('utf-8').split('\n')[1]
            if "Signed" not in signature:
                # print(f"{name} is not digitally signed.")
                unsigned_drivers.append(name)
            else:
                # print(f"{name} is digitally signed and trusted.")
                signed_drivers.append(name)
        except subprocess.CalledProcessError as e:
            # False error raised by subprocess, check as normal
            if "Signed" not in (f"{e.output}"):
                # print(f"{name} is not digitally signed.")
                unsigned_drivers.append(name)
            else:
                # print(f"{name} is digitally signed and trusted.")
                signed_drivers.append(name)
    # print(signed_drivers)
    # print("-------------------------------------------")
    # print(unsigned_drivers)
    return signed_drivers, unsigned_drivers


get_driver_signatures()

# import os
# import ctypes
# import sys
# import platform

# def is_driver_signed(driver_path):
#     try:
#         # Load required Windows DLLs
#         kernel32 = ctypes.WinDLL("kernel32.dll")
#         crypt32 = ctypes.WinDLL("crypt32.dll")
#         wintrust = ctypes.WinDLL("wintrust.dll")

#         # GUIDs for WintrustVerifyGuid
#         guid_action_verify = ctypes.create_string_buffer(b"{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}")
#         driver_policy_guid = ctypes.create_string_buffer(b"{F750E6C3-38EE-11d1-85E5-00C04FC295EE}")

#         # Define structures
#         class WINTRUST_FILE_INFO(ctypes.Structure):
#             _fields_ = [("cbStruct", ctypes.c_ulong),
#                         ("pcwszFilePath", ctypes.c_wchar_p),
#                         ("hFile", ctypes.c_void_p),
#                         ("pgKnownSubject", ctypes.c_void_p)]

#         # Function declarations
#         wintrust.WinVerifyTrust.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
#         wintrust.WinVerifyTrust.restype = ctypes.c_long

#         # Set up WINTRUST_FILE_INFO structure
#         file_info = WINTRUST_FILE_INFO()
#         file_info.cbStruct = ctypes.sizeof(file_info)
#         file_info.pcwszFilePath = driver_path

#         # Call WinVerifyTrust
#         result = wintrust.WinVerifyTrust(None, driver_policy_guid, ctypes.byref(file_info))

#         # Check the result
#         if result == 0:
#             return True
#         elif result == 2148204800:  # 0x800B0100
#             return False
#         else:
#             print("Error:", os.strerror(ctypes.GetLastError()))
#             return False
#     except Exception as e:
#         print("Error:", e)
#         return False

# def get_driver_list():
#     signed_drivers = []
#     unsigned_drivers = []
#     system_drive = os.getenv("SystemDrive")
#     drivers_folder = os.path.join(system_drive, "\\Windows\\System32\\drivers")
#     for driver in os.listdir(drivers_folder):
#         driver_path = os.path.join(drivers_folder, driver)
#         if os.path.isfile(driver_path):
#             if is_driver_signed(driver_path):
#                 signed_drivers.append(driver)
#             else:
#                 unsigned_drivers.append(driver)
#     return signed_drivers, unsigned_drivers

# if __name__ == "__main__":
#     signed_drivers, unsigned_drivers = get_driver_list()
#     print("Signed Drivers:")
#     print("\n".join(signed_drivers))
#     print("\nUnsigned Drivers:")
#     print("\n".join(unsigned_drivers))
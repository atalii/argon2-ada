--  This Source Code Form is subject to the terms of the Mozilla Public License,
--  v. 2.0. If a copy of the MPL was not distributed with this file, You can
--  obtain one at https://mozilla.org/MPL/2.0/.

with Interfaces.C;
with System;

with Ada.Strings.Unbounded;

package Argon2Ada is
   use Ada.Strings.Unbounded;

   Unreachable : exception;
   --  An Argon2Ada.Unreachable exception should never be thrown, but is used
   --  to indicate cases where the underlying c lib behaves unexpectedly or
   --  outside of its specification.

   subtype Error is Integer range -35 .. 0;

   Error_Names : array (Error) of Unbounded_String :=
      (0 => To_Unbounded_String ("Ok"),
      -1 => To_Unbounded_String ("Output_Ptr_Null"),
      -2 => To_Unbounded_String ("Output_Ptr_Too_Short"),
      -3 => To_Unbounded_String ("Output_Ptr_Too_Long"),
      -4 => To_Unbounded_String ("Pwd_Too_Short"),
      -5 => To_Unbounded_String ("Pwd_Too_Long"),
      -6 => To_Unbounded_String ("Salt_Too_Short"),
      -7 => To_Unbounded_String ("Salt_Too_Long"),
      -8 => To_Unbounded_String ("AD_Too_Short"),
      -9 => To_Unbounded_String ("AD_Too_Long"),
      -10 => To_Unbounded_String ("Secret_Too_Short"), 
      -11 => To_Unbounded_String ("Secret_Too_Long"),
      -12 => To_Unbounded_String ("Time_Too_Small"),
      -13 => To_Unbounded_String ("Time_Too_Large"),
      -14 => To_Unbounded_String ("Memory_Too_Little"),
      -15 => To_Unbounded_String ("Memory_Too_Much"),
      -16 => To_Unbounded_String ("Lanes_Too_Few"),
      -17 => To_Unbounded_String ("Lanes_Too_Many"),
      -18 => To_Unbounded_String ("Pwd_Ptr_Mismatch"),
      -19 => To_Unbounded_String ("Salt_Ptr_Mismatch"),
      -20 => To_Unbounded_String ("Secret_Ptr_Mismatch"),
      -21 => To_Unbounded_String ("AD_Ptr_Mismatch"),
      -22 => To_Unbounded_String ("Memory_Allocation_Error"),
      -23 => To_Unbounded_String ("Free_Memory_CBK_Null"),
      -24 => To_Unbounded_String ("Allocate_Memory_CBK_Null"),
      -25 => To_Unbounded_String ("Incorrect_Parameter"),
      -26 => To_Unbounded_String ("Incorrect_Type"),
      -27 => To_Unbounded_String ("Out_Ptr_Mismatch"),
      -28 => To_Unbounded_String ("Threads_Too_Few"),
      -29 => To_Unbounded_String ("Threads_Too_Many"),
      -30 => To_Unbounded_String ("Missing_Args"),
      -31 => To_Unbounded_String ("Encoding_Fail"),
      -32 => To_Unbounded_String ("Decoding_Fail"),
      -33 => To_Unbounded_String ("Thread_Fail"),
      -34 => To_Unbounded_String ("Decoding_Length_Fail"),
      -35 => To_Unbounded_String ("Verify_Mismatch"));

   type Uint8 is mod 2**8;
   type Uint32 is mod 2**32;

   subtype Valid_Salt_Len is Uint8 range 8 .. Uint8'Last;

   subtype Length is Uint32;
   subtype Required_Length is Length range 1 .. Length'Last;

   Disable : Length := 0;
   --  Wherever a length is required, Disable can be given to use 0-sized arrays
   --  and disable the corresponding feature if any.

   type Byte_Buf is array (Positive range <>) of Uint8;

   type Alg_Type is (D, I, ID);
   for Alg_Type use (D => 0, I => 1, ID => 2);

   type Flag is (Wipe_None, Wipe_Password, Wipe_Secret, Wipe_Both);
   for Flag use
      (Wipe_None => 2#00#, Wipe_Password => 2#01#,
      Wipe_Secret => 2#10#, Wipe_Both => 2#11#);

   subtype Version is Uint32;

   Version_10 : Version := 16#10#;
   Version_13 : Version := 16#13#;
   Version_Number : Version := Version_13;

   generic
      Output_Len : Required_Length;
      Pass_Len : Required_Length;

      Salt_Len : Valid_Salt_Len := 16;
      -- A 16 bit salt length is recommended for password hashing, though more
      -- bits and more entropy is not discouraged.

      Secret_Len : Length := Disable;
      Associated_Data_Len : Length := Disable;

   package Hasher is

      type Result_Buf is new Byte_Buf (1 .. Integer (Output_Len));
      type Pass_Buf   is new Byte_Buf (1 .. Integer (Pass_Len));
      type Salt_Buf   is new Byte_Buf (1 .. Integer (Salt_Len));
      type Secret_Buf is new Byte_Buf (1 .. Integer (Secret_Len));
      type AD_Buf     is new Byte_Buf (1 .. Integer (Associated_Data_Len));

      pragma Convention (Convention => C, Entity => Result_Buf);
      pragma Convention (Convention => C, Entity => Pass_Buf);
      pragma Convention (Convention => C, Entity => Salt_Buf);
      pragma Convention (Convention => C, Entity => AD_Buf);

      function Fill_Pass_Buf (Pass : String) return Pass_Buf;

      type Config is tagged record
         Time_Cost : Uint32;
         Mem_Cost : Uint32;
         Lanes : Uint32;

         Alg : Alg_Type;
         Version : Uint32;

         Flags : Flag;
      end record;

      type Result (Ok : Boolean := True) is record
         case Ok is
            when True =>
               Data : Result_Buf;
            when False =>
               Err : Error;
         end case;
      end record;

      function Hash
         (C : Config;
         Pass : in out Pass_Buf;
         Salt : in out Salt_Buf;
         Secret : Secret_Buf := (others => 0);
         AD : AD_Buf := (others => 0))
         return Result;
   end Hasher;

   function Buffer_To_String_Hex (Buffer : Byte_Buf) return String;

   function Type_To_String (Alg : Alg_Type) return String;
   --  A wrapper of argon2_type2string, but we don't have to worry about
   --  Alg_Type being invalid and returning NULL.

   -- function I_Hash_Encoded
   --    (Time_Cost : Uint32; Mem_Cost : Uint32; Parallelism : Uint32;
   --    Pwd : System.Address; Pwd_Len : Interfaces.C.size_t;
   --    Salt : System.Address; Salt_Len : Interfaces.C.size_t;
   --    Hash_Len : Interfaces.C.size_t; Encoded : Interfaces.C.char_array;
   --    Encoded_Len : Interfaces.C.size_t) return Error;
   -- -- A wrapper of argon2i_hash_encoded. TODO: make this a thicker wrapper.

   -- function I_Hash_Raw
   --    (Time_Cost : Uint32; Mem_Cost : Uint32; Parallelism : Uint32;
   --    Pwd : System.Address; Pwd_Len : Interfaces.C.size_t;
   --    Salt : System.Address; Salt_Len : Interfaces.C.size_t;
   --    Hash : System.Address; Hash_Len : Interfaces.C.size_t) return Error;

   -- function D_Hash_Encoded
   --    (Time_Cost : Uint32; Mem_Cost : Uint32; Parallelism : Uint32;
   --    Pwd : System.Address; Pwd_Len : Interfaces.C.size_t;
   --    Salt : System.Address; Salt_Len : Interfaces.C.size_t;
   --    Hash_Len : Interfaces.C.size_t; Encoded : Interfaces.C.char_array;
   --    Encoded_Len : Interfaces.C.size_t) return Error;
   -- -- A wrapper of argon2i_hash_encoded. TODO: make this a thicker wrapper.

   -- function D_Hash_Raw
   --    (Time_Cost : Uint32; Mem_Cost : Uint32; Parallelism : Uint32;
   --    Pwd : System.Address; Pwd_Len : Interfaces.C.size_t;
   --    Salt : System.Address; Salt_Len : Interfaces.C.size_t;
   --    Hash : System.Address; Hash_Len : Interfaces.C.size_t) return Error;

   -- function ID_Hash_Encoded
   --    (Time_Cost : Uint32; Mem_Cost : Uint32; Parallelism : Uint32;
   --    Pwd : System.Address; Pwd_Len : Interfaces.C.size_t;
   --    Salt : System.Address; Salt_Len : Interfaces.C.size_t;
   --    Hash_Len : Interfaces.C.size_t; Encoded : Interfaces.C.char_array;
   --    Encoded_Len : Interfaces.C.size_t) return Error;
   -- -- A wrapper of argon2id_hash_encoded. TODO: make this a thicker wrapper.

   -- function ID_Hash_Raw
   --    (Time_Cost : Uint32; Mem_Cost : Uint32; Parallelism : Uint32;
   --    Pwd : System.Address; Pwd_Len : Interfaces.C.size_t;
   --    Salt : System.Address; Salt_Len : Interfaces.C.size_t;
   --    Hash : System.Address; Hash_Len : Interfaces.C.size_t) return Error;

   -- function Hash
   --    (Time_Cost : Uint32; Mem_Cost : Uint32; Parallelism : Uint32;
   --    Pwd : System.Address; Pwd_Len : Interfaces.C.size_t;
   --    Salt : System.Address; Salt_Len : Interfaces.C.size_t;
   --    Hash : System.Address; Hash_Len : Interfaces.C.size_t;
   --    Encoded_Len : Interfaces.C.size_t;
   --    T : Alg_Type; V : Version) return Error;
private

end Argon2Ada;

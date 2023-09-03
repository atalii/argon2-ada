--  This Source Code Form is subject to the terms of the Mozilla Public License,
--  v. 2.0. If a copy of the MPL was not distributed with this file, You can
--  obtain one at https://mozilla.org/MPL/2.0/.

with Ada.Command_Line;
use Ada.Command_Line;

with Ada.Text_IO;
use Ada.Text_IO;

with Ada.Strings.Unbounded;
use Ada.Strings.Unbounded;

with System;
with System.Storage_Elements;

with Argon2Ada;

procedure Test
is

   package Test_Hasher is new Argon2Ada.Hasher (Output_Len => 128, Pass_Len => 64);

   Status : Exit_Status := 0;

   procedure Pass (M : String) is
   begin
      Put_Line ("PASS: " & M);
   end Pass;

   procedure Fail (M : String) is
   begin
      Put_Line ("FAIL: " & M);
   end Fail;

   procedure Update (S : String) is
   begin
      if Status = 0 then
         Pass (S);
      else
         Fail (S);
      end if;
   end Update;

   procedure Expect (A, B : String)
   is
      E : Boolean := A /= B;
   begin
      if E then
         Put_Line ("Expected: " & B);
         Put_Line ("Got: " & A);
         Status := 1;
      end if;
   end Expect;

   procedure Expect_Bool (A : Boolean)
   is begin
      if not A then
         Put_Line ("Expected: TRUE");
         Status := 1;
      end if;
   end Expect_Bool;

   procedure Type_To_String
   is
      Type_D : constant String := Argon2Ada.Type_To_String (Argon2Ada.D);
      Type_I : constant String := Argon2Ada.Type_To_String (Argon2Ada.I);
      Type_ID : constant String := Argon2Ada.Type_To_String (Argon2Ada.ID);
   begin
      Expect (Type_D,  "Argon2d");
      Expect (Type_I,  "Argon2i");
      Expect (Type_ID, "Argon2id");

      Update ("Type_To_String");
   end Type_To_String;

   procedure Hash
   is

      X : constant String := "07c9d62f370fb862ccd71310c0015934886a28bb606d6d5bbf4902d24ebf5ea1d1050ee6adcc2bea3344c44c0fbe1a532b98a44f73a4f3bbc7185782bb4d962355bff365e864fba0cafa02690612bc895d4a3fc02b6ac9b4a67e7fd584ae5e908ad91a2e720779f8181907686893f55cb84c69c2b0b8651e441272907c4c02ab";
      Password : Test_Hasher.Pass_Buf := Test_Hasher.Fill_Pass_Buf ("correct horse battery staple");
      Salt : Test_Hasher.Salt_Buf := (others => 0);

      Conf : constant Test_Hasher.Config :=
         (Time_Cost => 1, Mem_Cost => 64, Lanes => 8, Threads => 8,

         Version => Argon2Ada.Version_13,
         Alg => Argon2Ada.ID,
         Flags => Argon2Ada.Wipe_None);

      Basic_R : constant Test_Hasher.Result := Conf.Hash (Password, Salt);

   begin
      Expect_Bool (Basic_R.Ok);
      if Basic_R.Ok then
         Expect (Argon2Ada.Buffer_To_String_Hex (Argon2Ada.Byte_Buf (Basic_R.Data)), X);
      end if;

      Update ("Hash");
   end Hash;

begin

   Type_To_String;
   Hash;

   Set_Exit_Status (Status);

end Test;

﻿namespace B2BApp.DTOs
{
    public class BaseObjectId
    {
        public int TimeStamp { get; set; }
        public int Machine { get; set; }
        public int Increment { get; set; }
        public int Pid { get; set; }
        public DateTime CreationTime { get; set; }

    }
}
